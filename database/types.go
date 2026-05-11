package database

import (
	"database/sql"
	"time"

	"watgbridge/state"
)

type MsgIdPair struct {
	// WhatsApp
	ID            string `gorm:"primaryKey;"` // Message ID
	ParticipantId string // Sender JID
	WaChatId      string // Chat JID

	// Telegram
	TgChatId   int64
	TgThreadId int64
	TgMsgId    int64

	MarkRead sql.NullBool
}

type ChatThreadPair struct {
	ID         string `gorm:"primaryKey;"` // WhatsApp Chat ID
	TgChatId   int64  // Telegram Chat ID
	TgThreadId int64  // Telegram Thread ID (Topics)
}

type ContactName struct {
	ID           string `gorm:"primaryKey;"` // WhatsApp Contact JID
	FirstName    string
	FullName     string
	PushName     string
	BusinessName string
	Server       string
}

type ChatEphemeralSettings struct {
	ID             string `gorm:"primaryKey;"` // WhatsApp Chat ID
	IsEphemeral    bool
	EphemeralTimer uint32
}

type MiniAppTimelineMessage struct {
	ID uint64 `gorm:"primaryKey;autoIncrement"`

	WaChatID           string `gorm:"index;not null"`
	WaMessageID        string `gorm:"index"`
	ReplyToWaMessageID string
	SenderJID          string
	SenderName         string
	Direction          string
	Source             string
	Text               string `gorm:"type:text"`
	MediaType          string
	MediaName          string
	Status             string
	ErrorMessage       string    `gorm:"type:text"`
	CreatedAt          time.Time `gorm:"index"`
}

func AutoMigrate() error {
	db := state.State.Database
	return db.AutoMigrate(
		&MsgIdPair{},
		&ChatThreadPair{},
		&ContactName{},
		&ChatEphemeralSettings{},
		&MiniAppTimelineMessage{},
	)
}
