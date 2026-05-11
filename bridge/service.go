package bridge

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"strings"

	"watgbridge/database"
	"watgbridge/state"
	"watgbridge/utils"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	waTypes "go.mau.fi/whatsmeow/types"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

func IsAuthorizedTelegramUser(userID int64) bool {
	cfg := state.State.Config
	if userID == cfg.Telegram.OwnerID {
		return true
	}
	for _, sudoUserID := range cfg.Telegram.SudoUsersID {
		if sudoUserID == userID {
			return true
		}
	}
	return false
}

func SendTextToWhatsApp(waChatID, text, replyToWaMessageID string) (whatsmeow.SendResponse, error) {
	waClient := state.State.WhatsAppClient

	chatJID, ok := utils.WaParseJID(waChatID)
	if !ok {
		return whatsmeow.SendResponse{}, fmt.Errorf("invalid WhatsApp chat ID")
	}

	msg := &waE2E.Message{
		Conversation: proto.String(text),
	}

	if replyToWaMessageID != "" {
		participant := chatJID.ToNonAD().String()
		if previous, err := database.MiniAppTimelineGetByWaMessage(chatJID.String(), replyToWaMessageID); err == nil && previous != nil && previous.SenderJID != "" {
			participant = previous.SenderJID
		}
		msg = &waE2E.Message{
			ExtendedTextMessage: &waE2E.ExtendedTextMessage{
				Text: proto.String(text),
				ContextInfo: &waE2E.ContextInfo{
					StanzaID:      proto.String(replyToWaMessageID),
					Participant:   proto.String(participant),
					QuotedMessage: &waE2E.Message{Conversation: proto.String("")},
				},
			},
		}
	}

	return waClient.SendMessage(context.Background(), chatJID, msg)
}

func SendMediaToWhatsApp(waChatID, caption, replyToWaMessageID string, file multipart.File, fileHeader *multipart.FileHeader, mimeType string) (whatsmeow.SendResponse, error) {
	waClient := state.State.WhatsAppClient

	chatJID, ok := utils.WaParseJID(waChatID)
	if !ok {
		return whatsmeow.SendResponse{}, fmt.Errorf("invalid WhatsApp chat ID")
	}

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return whatsmeow.SendResponse{}, err
	}

	var mediaType whatsmeow.MediaType
	if strings.HasPrefix(mimeType, "image/") {
		mediaType = whatsmeow.MediaImage
	} else if strings.HasPrefix(mimeType, "video/") {
		mediaType = whatsmeow.MediaVideo
	} else if strings.HasPrefix(mimeType, "audio/") {
		mediaType = whatsmeow.MediaAudio
	} else {
		mediaType = whatsmeow.MediaDocument
	}

	uploadedMedia, err := waClient.Upload(context.Background(), fileBytes, mediaType)
	if err != nil {
		return whatsmeow.SendResponse{}, err
	}

	var contextInfo *waE2E.ContextInfo
	if replyToWaMessageID != "" {
		participant := chatJID.ToNonAD().String()
		if previous, err := database.MiniAppTimelineGetByWaMessage(chatJID.String(), replyToWaMessageID); err == nil && previous != nil && previous.SenderJID != "" {
			participant = previous.SenderJID
		}
		contextInfo = &waE2E.ContextInfo{
			StanzaID:      proto.String(replyToWaMessageID),
			Participant:   proto.String(participant),
			QuotedMessage: &waE2E.Message{Conversation: proto.String("")},
		}
	}

	msg := &waE2E.Message{
		DocumentMessage: &waE2E.DocumentMessage{
			Caption:       proto.String(caption),
			Title:         proto.String(fileHeader.Filename),
			FileName:      proto.String(fileHeader.Filename),
			URL:           proto.String(uploadedMedia.URL),
			DirectPath:    proto.String(uploadedMedia.DirectPath),
			MediaKey:      uploadedMedia.MediaKey,
			Mimetype:      proto.String(mimeType),
			FileEncSHA256: uploadedMedia.FileEncSHA256,
			FileSHA256:    uploadedMedia.FileSHA256,
			FileLength:    proto.Uint64(uint64(len(fileBytes))),
			ContextInfo:   contextInfo,
		},
	}

	if mediaType == whatsmeow.MediaImage {
		msg = &waE2E.Message{
			ImageMessage: &waE2E.ImageMessage{
				Caption:       proto.String(caption),
				URL:           proto.String(uploadedMedia.URL),
				DirectPath:    proto.String(uploadedMedia.DirectPath),
				MediaKey:      uploadedMedia.MediaKey,
				Mimetype:      proto.String(mimeType),
				FileEncSHA256: uploadedMedia.FileEncSHA256,
				FileSHA256:    uploadedMedia.FileSHA256,
				FileLength:    proto.Uint64(uint64(len(fileBytes))),
				ContextInfo:   contextInfo,
			},
		}
	}

	return waClient.SendMessage(context.Background(), chatJID, msg)
}

func RevokeWhatsAppMessage(waChatID, waMessageID string) error {
	waClient := state.State.WhatsAppClient
	chatJID, ok := utils.WaParseJID(waChatID)
	if !ok {
		return fmt.Errorf("invalid WhatsApp chat ID")
	}

	revokeMessage := waClient.BuildRevoke(chatJID, waTypes.EmptyJID, waMessageID)
	_, err := waClient.SendMessage(context.Background(), chatJID, revokeMessage)
	return err
}

func RecordTimelineMessage(msg database.MiniAppTimelineMessage) {
	if _, err := database.MiniAppTimelineAdd(&msg); err != nil {
		state.State.Logger.Warn("failed to persist mini app timeline message", zap.Error(err))
	}
}
