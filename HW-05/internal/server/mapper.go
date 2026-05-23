package server

import (
	"hw05chat/internal/domain"
	"hw05chat/internal/protocol/chatpb"
)

func imageFromPB(in *chatpb.Image) *domain.Image {
	if in == nil {
		return nil
	}
	return &domain.Image{
		MimeType: in.GetMimeType(),
		Data:     append([]byte(nil), in.GetData()...),
		Size:     in.GetSizeBytes(),
	}
}

func imageToPB(in *domain.Image) *chatpb.Image {
	if in == nil {
		return nil
	}
	return &chatpb.Image{
		MimeType:  in.MimeType,
		Data:      append([]byte(nil), in.Data...),
		SizeBytes: in.Size,
	}
}

func messageToPB(in domain.Message) *chatpb.ChatMessage {
	out := &chatpb.ChatMessage{
		Id:       in.ID,
		From:     in.From,
		Text:     in.Text,
		UnixTime: in.UnixTime,
		Private:  in.Private,
	}
	if in.To != "" {
		out.To = &in.To
	}
	if in.Image != nil {
		out.Image = imageToPB(in.Image)
	}
	if in.SenderIcon != nil {
		out.SenderIcon = imageToPB(in.SenderIcon)
	}
	return out
}

func historyToPB(in domain.History) *chatpb.History {
	out := &chatpb.History{
		Messages: make([]*chatpb.ChatMessage, 0, len(in.Messages)),
		Images:   make([]*chatpb.Image, 0, len(in.Images)),
		Users:    make([]*chatpb.User, 0, len(in.Users)),
	}
	for _, msg := range in.Messages {
		out.Messages = append(out.Messages, messageToPB(msg))
	}
	for i := range in.Images {
		out.Images = append(out.Images, imageToPB(&in.Images[i]))
	}
	if in.LastImage != nil {
		out.LastImage = imageToPB(in.LastImage)
	}
	for _, user := range in.Users {
		profile := &chatpb.User_Profile{}
		if user.Icon != nil {
			profile.Icon = imageToPB(user.Icon)
			profile.HasIcon = true
		}
		out.Users = append(out.Users, &chatpb.User{Name: user.Name, Profile: profile})
	}
	return out
}
