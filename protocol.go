package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"strings"
)

var (
	FrameMagic    = []byte("TDV2")
	FrameVersion  = uint8(2)
	UDPBatchMagic = []byte("TDU2")
	UDPVersion    = uint8(1)

	// Dos sobres autenticados:
	//   TDS2 (legacy): HMAC only, payload en claro. Solo se lee para compat.
	//   TDS3 (secure): HMAC + AES-GCM. Default cuando ENCRYPTION_ENABLED=true.
	EnvelopeMagicLegacy = []byte("TDS2")
	EnvelopeMagicSecure = []byte("TDS3")
	TagSize             = 32 // sha256.Size
	NonceSize           = 12 // GCM standard
)

const (
	FrameHeaderSize    = 4 + 1 + 8 + 4 + 4
	UDPBatchHeaderSize = 4 + 1 + 8 + 2
	UDPItemHeaderSize  = 2 + 1 + 1 + 4
)

type UDPPacket struct {
	Host    string
	Port    uint16
	Payload []byte
}

func QueueKey(slot int) string {
	if slot <= 0 {
		return "_v2_queue.txt"
	}
	return fmt.Sprintf("_v2_queue_%d.txt", slot)
}
func TargetKey(id string) string { return fmt.Sprintf("_v2_target_%s.json", id) }
func StatusKey(id string) string { return fmt.Sprintf("_v2_status_%s.json", id) }
func CloseKey(id string) string  { return fmt.Sprintf("_v2_close_%s.txt", id) }
func DataKey(dir, id string, seq uint64) string {
	return fmt.Sprintf("_v2_%s_%s_%016d.bin", dir, id, seq)
}
func UDPDataKey(dir, id string, seq uint64) string {
	return fmt.Sprintf("_v2_udp_%s_%s_%016d.bin", dir, id, seq)
}
func AckKey(dir, id string) string { return fmt.Sprintf("_v2_ack_%s_%s.txt", dir, id) }
func FinKey(dir, id string) string { return fmt.Sprintf("_v2_fin_%s_%s.txt", dir, id) }

func EncodeFrame(seq uint64, payload []byte) []byte {
	out := make([]byte, FrameHeaderSize+len(payload))
	copy(out[0:4], FrameMagic)
	out[4] = FrameVersion
	binary.BigEndian.PutUint64(out[5:13], seq)
	binary.BigEndian.PutUint32(out[13:17], uint32(len(payload)))
	crc := crc32.ChecksumIEEE(payload)
	binary.BigEndian.PutUint32(out[17:21], crc)
	copy(out[21:], payload)
	return out
}

func DecodeFrame(raw []byte, expectedSeq uint64) ([]byte, error) {
	if len(raw) < FrameHeaderSize {
		return nil, errors.New("truncado")
	}
	if string(raw[:4]) != string(FrameMagic) || raw[4] != FrameVersion {
		return nil, errors.New("firma incorrecta")
	}
	if binary.BigEndian.Uint64(raw[5:13]) != expectedSeq {
		return nil, errors.New("secuencia incorrecta")
	}
	if uint32(len(raw[21:])) != binary.BigEndian.Uint32(raw[13:17]) {
		return nil, errors.New("longitud incorrecta")
	}
	if crc32.ChecksumIEEE(raw[21:]) != binary.BigEndian.Uint32(raw[17:21]) {
		return nil, errors.New("CRC incorrecto")
	}
	return raw[21:], nil
}

func encodeHost(host string) (uint8, []byte, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return 0, nil, errors.New("vacío")
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			return 1, ipv4, nil
		}
		return 4, ip.To16(), nil
	}
	b := []byte(host)
	if len(b) > 255 {
		return 0, nil, errors.New("muy largo")
	}
	return 3, b, nil
}

func decodeHost(atyp uint8, raw []byte) (string, error) {
	if atyp == 1 && len(raw) == 4 {
		return net.IP(raw).String(), nil
	}
	if atyp == 4 && len(raw) == 16 {
		return net.IP(raw).String(), nil
	}
	if atyp == 3 {
		return string(raw), nil
	}
	return "", errors.New("atyp incorrecto")
}

func EncodeUDPBatch(seq uint64, items []UDPPacket) ([]byte, error) {
	var out []byte
	h := make([]byte, UDPBatchHeaderSize)
	copy(h[:4], UDPBatchMagic)
	h[4] = UDPVersion
	binary.BigEndian.PutUint64(h[5:13], seq)
	binary.BigEndian.PutUint16(h[13:15], uint16(len(items)))
	out = append(out, h...)
	for _, item := range items {
		atyp, hostBytes, err := encodeHost(item.Host)
		if err != nil {
			return nil, err
		}
		ih := make([]byte, UDPItemHeaderSize)
		binary.BigEndian.PutUint16(ih[:2], item.Port)
		ih[2] = atyp
		ih[3] = uint8(len(hostBytes))
		binary.BigEndian.PutUint32(ih[4:8], uint32(len(item.Payload)))
		out = append(out, ih...)
		out = append(out, hostBytes...)
		out = append(out, item.Payload...)
	}
	return out, nil
}

func DecodeUDPBatch(raw []byte, expectedSeq uint64) ([]UDPPacket, error) {
	if len(raw) < UDPBatchHeaderSize {
		return nil, errors.New("truncado")
	}
	if string(raw[:4]) != string(UDPBatchMagic) || raw[4] != UDPVersion {
		return nil, errors.New("firma udp incorrecta")
	}
	if binary.BigEndian.Uint64(raw[5:13]) != expectedSeq {
		return nil, errors.New("secuencia udp incorrecta")
	}
	count := binary.BigEndian.Uint16(raw[13:15])
	offset := UDPBatchHeaderSize
	packets := make([]UDPPacket, 0, count)
	for i := 0; i < int(count); i++ {
		if offset+UDPItemHeaderSize > len(raw) {
			return nil, errors.New("truncado en item header")
		}
		port := binary.BigEndian.Uint16(raw[offset : offset+2])
		atyp := raw[offset+2]
		hostLen := int(raw[offset+3])
		payloadLen := int(binary.BigEndian.Uint32(raw[offset+4 : offset+8]))
		offset += UDPItemHeaderSize
		endHost := offset + hostLen
		endPayload := endHost + payloadLen
		if endPayload > len(raw) {
			return nil, errors.New("truncado en payload")
		}
		host, _ := decodeHost(atyp, raw[offset:endHost])
		packets = append(packets, UDPPacket{Host: host, Port: port, Payload: raw[endHost:endPayload]})
		offset = endPayload
	}
	return packets, nil
}

func EncodeCounter(val uint64) []byte { return []byte(strconv.FormatUint(val, 10)) }
func DecodeCounter(raw []byte) uint64 {
	if len(raw) == 0 {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	return v
}
