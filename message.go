package gostashcat

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"strconv"
)

type Conversation struct {
	ID           string `json:"id"`
	Name         string `json:"name,omitempty"`
	Created      string `json:"created"`
	LastAction   string `json:"last_action"`
	LastActivity string `json:"last_activity"`
	Encrypted    bool   `json:"encrypted"`

	// Members []User `json:"members"`

	UserCount      int    `json:"user_count"`
	UnreadMessages int    `json:"unread_messages"`
	Key            string `json:"key"`

	// others are ignored for now
}

type ConversationResponsePayload struct {
	Conversation Conversation `json:"conversation"`
}

type ConversationResponse struct {
	Status    Status                      `json:"status"`
	Payload   ConversationResponsePayload `json:"payload"`
	Signature string                      `json:"signature"`
}

type UserIDKeyCombination struct {
	UserID  string
	UserKey string
}

type Message struct {
	ID             int    `json:"id"`
	Text           string `json:"text"`
	ConversationID int    `json:"conversation_id,omitempty"`
	ChannelID      int    `json:"channel_id,omitempty"`
	ThreadID       int    `json:"thread_id,omitempty"`
	Hash           string `json:"hash"`
	Verification   string `json:"verification"`
	Sender         User   `json:"sender"`
	IV             string `json:"iv"`
	Alarm          bool   `json:"alarm"`
	Kind           string `json:"kind"`
	Encrypted      bool   `json:"encrypted"`
	SendTime       int    `json:"time,string"`
	DeleteTime     int    `json:"deleted,string,omitempty"`
	IsForwarded    bool   `json:"is_forwarded"`
	DeviceID       string `json:"devicce_id"`
	Type           string `json:"type"`
}

type MessageResponsePayload struct {
	Message Message `json:"message"`
}

type MessageContentResponsePayload struct {
	Messages []map[string]interface{} `json:"messages"`
}

type MessageResponse struct {
	Status    Status                 `json:"status"`
	Payload   MessageResponsePayload `json:"payload"`
	Signature string                 `json:"signature"`
}

type MessageContentResponse struct {
	Status    Status                        `json:"status"`
	Payload   MessageContentResponsePayload `json:"payload"`
	Signature string                        `json:"signature"`
}

type IDKeyCombo struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

func (api *Client) CreateConversation(users []User) (Conversation, error) {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)

	// generate new symmetric encryption key for conversation
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return Conversation{}, err
	}

	members := []IDKeyCombo{}
	for _, elem := range users {
		block, _ := pem.Decode([]byte(elem.PublicKey))
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return Conversation{}, err
		}
		encryptedSecret, err := encryptRSA(secret, pubKey.(*rsa.PublicKey))
		if err != nil {
			return Conversation{}, err
		}
		members = append(members, IDKeyCombo{
			elem.ID,
			encryptedSecret,
		})
	}

	b, err := json.Marshal(members)
	if err != nil {
		return Conversation{}, err
	}

	// json encoded [{id, key},...]
	v.Set("members", string(b))

	response := ConversationResponse{}

	err = api.postMethod("message/createEncryptedConversation", v, &response)
	if err != nil {
		return Conversation{}, err
	}

	return response.Payload.Conversation, nil
}

func (api *Client) decryptKey(key string) ([]byte, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return []byte{}, err
	}

	rng := rand.Reader
	decryptedKey, err := rsa.DecryptOAEP(sha1.New(), rng, &api.privateKey, decodedKey, []byte(""))
	if err != nil {
		return []byte{}, err
	}

	return decryptedKey, nil
}

func (api *Client) sendMessageToConversation(conversation Conversation, plainMessage string, alarm bool) (Message, error) {
	if !conversation.Encrypted {
		return Message{}, fmt.Errorf("Unencrypted conversations are not supported (id: %s)", conversation.ID)
	}

	decryptedConversationKey, err := api.decryptKey(conversation.Key)
	if err != nil {
		return Message{}, err
	}

	ciphertext, iv, err := encryptAES([]byte(plainMessage), decryptedConversationKey)
	if err != nil {
		return Message{}, err
	}

	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("target", "conversation")
	v.Set("conversation_id", conversation.ID)
	v.Set("text", ciphertext)
	v.Set("iv", iv)
	v.Set("encrypted", strconv.FormatBool(conversation.Encrypted))
	// The verification field seems to get ignored by all parts of stashcat currently
	// According to the webclient this is an md5 hash of:
	// the (encrypted) message (or "") + api.deviceID + timestamp + id of first file (or "") + longitude.replace(".", "") + latitude.replace(".", "")
	// As the timestamps does not seem to get transmitted anywhere and there's
	// no way for anyone to verify this "verification" and the server and all
	// available clients seem to just accept a message with this set to ""
	v.Set("verification", "")

	if alarm {
		v.Set("alarm", strconv.FormatBool(alarm))
	}

	response := MessageResponse{}
	err = api.postMethod("message/send", v, &response)
	if err != nil {
		return Message{}, err
	}

	return response.Payload.Message, nil
}

func (api *Client) SendMessageToConversation(conversation Conversation, plainMessage string) (Message, error) {
	return api.sendMessageToConversation(conversation, plainMessage, false)
}

func (api *Client) SendAlarmMessageToConversation(conversation Conversation, plainMessage string) (Message, error) {
	return api.sendMessageToConversation(conversation, plainMessage, true)
}

func (api *Client) sendMessageToUser(userID int, message string, alarm bool) (Message, error) {
	user, err := api.GetUserInfo(userID)
	if err != nil {
		return Message{}, err
	}

	conv, err := api.CreateConversation([]User{
		user,
		api.UserInfo,
	})
	if err != nil {
		return Message{}, err
	}

	msg, err := api.sendMessageToConversation(conv, message, alarm)
	if err != nil {
		return Message{}, err
	}

	return msg, nil
}

// SendMessageToUser is a wrapper to creating a new conversation with a single user and sending a message to it
func (api *Client) SendMessageToUser(userID int, message string) (Message, error) {
	return api.sendMessageToUser(userID, message, false)
}

// Wrapper to creating a new conversation with user and sending a message to it
func (api *Client) SendAlarmMessageToUser(userID int, message string) (Message, error) {
	return api.sendMessageToUser(userID, message, true)
}

func (api *Client) SendMessageToChannel(channel ChannelInfo, plainMessage string) (Message, error) {
	if !channel.Encrypted {
		return Message{}, fmt.Errorf("Unencrypted channels are not supported (id: %d)", channel.ID)
	}

	decryptedKey, err := api.decryptKey(channel.Key)
	if err != nil {
		return Message{}, err
	}

	ciphertext, iv, err := encryptAES([]byte(plainMessage), decryptedKey)
	if err != nil {
		return Message{}, err
	}

	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("target", "channel")
	v.Set("channel_id", fmt.Sprintf("%d", channel.ID))
	v.Set("text", ciphertext)
	v.Set("iv", iv)
	v.Set("encrypted", strconv.FormatBool(channel.Encrypted))
	// The verification field seems to get ignored by all parts of stashcat currently
	// According to the webclient this is an md5 hash of:
	// the (encrypted) message (or "") + api.deviceID + timestamp + id of first file (or "") + longitude.replace(".", "") + latitude.replace(".", "")
	// As the timestamps does not seem to get transmitted anywhere and there's
	// no way for anyone to verify this "verification" and the server and all
	// available clients seem to just accept a message with this set to ""
	v.Set("verification", "")

	response := MessageResponse{}
	err = api.postMethod("message/send", v, &response)
	if err != nil {
		return Message{}, err
	}

	return response.Payload.Message, nil
}

func (api *Client) DecryptMessages(messages []Message, encryptedKey string) ([]Message, error) {
	decryptedKey, err := api.decryptKey(encryptedKey)
	if err != nil {
		return nil, err
	}

	decryptedMessages := []Message{}

	for _, m := range messages {
		if len(m.Text) > 0 {
			if m.Kind != "message" || !m.Encrypted {
				continue
			}
			text, err := decryptAESHex(m.Text, m.IV, decryptedKey)
			if err != nil {
				return nil, err
			}
			m.Text = text
		}
		decryptedMessages = append(decryptedMessages, m)
	}
	return decryptedMessages, nil
}

func (api *Client) decodeMessages(messages []map[string]interface{}) ([]Message, error) {
	var responseMessages []Message
	for _, msg := range messages {
		var resultMsg Message
		if msg["id"] != nil {
			jsonData, err := json.Marshal(msg)
			if err != nil {
				return nil, err
			}
			err = api.unmarshalBody(jsonData, &resultMsg)
			if err != nil {
				return nil, err
			}
			responseMessages = append(responseMessages, resultMsg)
		}
	}

	return responseMessages, nil
}

func (api *Client) GetChannelContent(channel ChannelInfo, limit, offset int) ([]Message, error) {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("source", "channel")
	v.Set("channel_id", fmt.Sprintf("%d", channel.ID))
	v.Set("limit", fmt.Sprintf("%d", limit))
	v.Set("offset", fmt.Sprintf("%d", offset))

	response := MessageContentResponse{}
	err := api.postMethod("message/content", v, &response)
	if err != nil {
		return nil, err
	}

	responseMessages, err := api.decodeMessages(response.Payload.Messages)
	if err != nil {
		return nil, err
	}

	return responseMessages, nil
}

func (api *Client) GetConversationContent(conversation Conversation, limit, offset int) ([]Message, error) {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("source", "conversation")
	v.Set("conversation_id", conversation.ID)
	v.Set("limit", fmt.Sprintf("%d", limit))
	v.Set("offset", fmt.Sprintf("%d", offset))

	response := MessageContentResponse{}
	err := api.postMethod("message/content", v, &response)
	if err != nil {
		return nil, err
	}

	responseMessages, err := api.decodeMessages(response.Payload.Messages)
	if err != nil {
		return nil, err
	}

	return responseMessages, nil
}
