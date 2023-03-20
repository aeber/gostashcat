package gostashcat

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"
	"strings"
	"time"
)

type Key struct {
	FileID  int    `json:"file_id"`
	Type    string `json:"type"`
	ChatID  int    `json:"chat_id,string"`
	Key     string `json:"key"`
	IV      string `json:"iv"`
	ChatKey string `json:"chat_key"`
}

type File struct {
	ID              int    `json:"id,string"`
	Name            string `json:"name"`
	SizeBytes       int    `json:"size_byte,string"`
	TypeID          int    `json:"type_id,string"`
	Ext             string `json:"ext"`
	Mime            string `json:"mime"`
	Uploaded        int    `json:"uploaded,string"`
	Modified        int    `json:"modified,string"`
	OwnerID         int    `json:"owner_id,string"`
	LastDownload    int    `json:"last_download,string"`
	TimesDownloaded int    `json:"times_downloaded,string"`
	Encrypted       bool   `json:"encrypted"`
	E2EIV           string `json:"e2e_iv"`
	MD5             string `json:"md5"`
	Keys            []Key  `json:"keys"`
}

func (api *Client) GetFile(f File) (string, error) {
	v := url.Values{}
	v.Set("id", fmt.Sprintf("%d", f.ID))

	var sb strings.Builder
	w := multipart.NewWriter(&sb)
	w.WriteField("client_key", api.clientKey)
	w.WriteField("device_id", api.deviceID)
	w.Close()

	ctx, cncl := context.WithTimeout(context.Background(), 300*time.Second)
	defer cncl()
	resp, err := api.postRequestMultipart(ctx, fmt.Sprintf("/file/download?%s", v.Encode()), w.Boundary(), strings.NewReader(sb.String()))
	if err != nil {
		api.Debugf("Request to get file %d failed: %v", f.ID, err)
		return "", err
	}
	defer resp.Body.Close()

	encryptedBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	decryptedChannelKey, err := api.decryptKey(f.Keys[0].ChatKey)
	if err != nil {
		api.Debugf("Decrypting of channel key failed while getting file %d: %v", f.ID, err)
		return "", err
	}

	decryptedFileKey, err := decryptAESHex(f.Keys[0].Key, f.Keys[0].IV, decryptedChannelKey)
	if err != nil {
		api.Debugf("Decrypting of file key failed while getting file %d: %v", f.ID, err)
		return "", err
	}

	iv, err := hex.DecodeString(f.E2EIV)
	if err != nil {
		return "", err
	}
	decryptedBody, err := decryptAES(encryptedBody, iv, []byte(decryptedFileKey))
	if err != nil {
		api.Debugf("Decrypting of file body failed while getting file %d: %v", f.ID, err)
		return "", err
	}

	return decryptedBody, nil
}
