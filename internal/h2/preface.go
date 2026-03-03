package h2

import (
	"bytes"
	"encoding/binary"
)

const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	frameTypeSettings     = 0x04
	frameTypePriority     = 0x02
	frameTypeWindowUpdate = 0x08
)

// BuildPreface 构建 HTTP/2 连接前言
func BuildPreface(cfg *FingerprintConfig) []byte {
	var buf bytes.Buffer

	buf.WriteString(clientPreface)

	settingsPayload := make([]byte, 6*len(cfg.Settings))
	for i, s := range cfg.Settings {
		binary.BigEndian.PutUint16(settingsPayload[i*6:], uint16(s.ID))
		binary.BigEndian.PutUint32(settingsPayload[i*6+2:], s.Val)
	}
	writeFrame(&buf, frameTypeSettings, 0x00, 0, settingsPayload)

	if cfg.WindowUpdateValue > 0 {
		wuPayload := make([]byte, 4)
		binary.BigEndian.PutUint32(wuPayload, cfg.WindowUpdateValue)
		writeFrame(&buf, frameTypeWindowUpdate, 0x00, 0, wuPayload)
	}

	if cfg.SendPriority && len(cfg.PriorityFrames) > 0 {
		for _, pf := range cfg.PriorityFrames {
			priPayload := BuildPriorityPayload(pf)
			writeFrame(&buf, frameTypePriority, 0x00, pf.StreamID, priPayload)
		}
	}

	return buf.Bytes()
}

// BuildPriorityPayload 构建 PRIORITY 帧的 payload
func BuildPriorityPayload(pf PriorityConfig) []byte {
	payload := make([]byte, 5)
	dep := pf.DependsOn
	if pf.Exclusive {
		dep |= 0x80000000
	}
	binary.BigEndian.PutUint32(payload[0:4], dep)
	payload[4] = pf.Weight
	return payload
}

func writeFrame(buf *bytes.Buffer, frameType byte, flags byte, streamID uint32, payload []byte) {
	length := len(payload)
	buf.WriteByte(byte(length >> 16))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length))
	buf.WriteByte(frameType)
	buf.WriteByte(flags)
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], streamID&0x7fffffff)
	buf.Write(sid[:])
	buf.Write(payload)
}
