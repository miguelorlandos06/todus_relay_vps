package main

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeFrame(t *testing.T) {
	payload := []byte("hello todus relay v2")
	enc := EncodeFrame(42, payload)
	if len(enc) != FrameHeaderSize+len(payload) {
		t.Fatalf("tamaño inesperado: %d", len(enc))
	}
	dec, err := DecodeFrame(enc, 42)
	if err != nil {
		t.Fatalf("decode falló: %v", err)
	}
	if !bytes.Equal(dec, payload) {
		t.Fatalf("payload mismatch: %q != %q", dec, payload)
	}
}

func TestDecodeFrameWrongSeq(t *testing.T) {
	enc := EncodeFrame(10, []byte("x"))
	if _, err := DecodeFrame(enc, 11); err == nil {
		t.Fatal("esperaba error de secuencia")
	}
}

func TestDecodeFrameCorruptedCRC(t *testing.T) {
	enc := EncodeFrame(1, []byte("payload"))
	enc[17] ^= 0xFF // corromper CRC
	if _, err := DecodeFrame(enc, 1); err == nil {
		t.Fatal("esperaba error de CRC")
	}
}

func TestEncodeDecodeCounter(t *testing.T) {
	for _, v := range []uint64{0, 1, 42, 1 << 40, ^uint64(0)} {
		enc := EncodeCounter(v)
		dec := DecodeCounter(enc)
		if dec != v {
			t.Fatalf("counter mismatch %d -> %d", v, dec)
		}
	}
}

func TestEncodeDecodeUDPBatch(t *testing.T) {
	items := []UDPPacket{
		{Host: "1.2.3.4", Port: 53, Payload: []byte("query")},
		{Host: "example.com", Port: 443, Payload: []byte("GET / HTTP/1.1\r\n")},
		{Host: "::1", Port: 5353, Payload: []byte("mDNS")},
	}
	enc, err := EncodeUDPBatch(7, items)
	if err != nil {
		t.Fatalf("encode falló: %v", err)
	}
	dec, err := DecodeUDPBatch(enc, 7)
	if err != nil {
		t.Fatalf("decode falló: %v", err)
	}
	if len(dec) != len(items) {
		t.Fatalf("count mismatch: %d != %d", len(dec), len(items))
	}
	for i, want := range items {
		got := dec[i]
		if got.Port != want.Port {
			t.Fatalf("port mismatch %d: %d != %d", i, got.Port, want.Port)
		}
		if got.Host != want.Host {
			t.Fatalf("host mismatch %d: %q != %q", i, got.Host, want.Host)
		}
		if !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("payload mismatch %d", i)
		}
	}
}

func TestDecodeUDPBatchWrongMagic(t *testing.T) {
	enc, _ := EncodeUDPBatch(1, []UDPPacket{{Host: "1.1.1.1", Port: 1, Payload: []byte("x")}})
	enc[0] = 'X'
	if _, err := DecodeUDPBatch(enc, 1); err == nil {
		t.Fatal("esperaba error de magic")
	}
}

func TestDecodeUDPBatchTruncated(t *testing.T) {
	enc, _ := EncodeUDPBatch(1, []UDPPacket{{Host: "1.1.1.1", Port: 1, Payload: []byte("x")}})
	if _, err := DecodeUDPBatch(enc[:UDPBatchHeaderSize-1], 1); err == nil {
		t.Fatal("esperaba error truncado")
	}
}

func TestKeyFunctionsStable(t *testing.T) {
	if QueueKey(0) != "_v2_queue.txt" {
		t.Fatalf("QueueKey(0) = %q", QueueKey(0))
	}
	if QueueKey(2) != "_v2_queue_2.txt" {
		t.Fatalf("QueueKey(2) = %q", QueueKey(2))
	}
	if DataKey("c2s", "abc", 5) != "_v2_c2s_abc_0000000000000005.bin" {
		t.Fatalf("DataKey = %q", DataKey("c2s", "abc", 5))
	}
}
