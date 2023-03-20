package gostashcat

import (
	"fmt"
	"net/url"
)

type Folder struct {
	ID       int    `json:"id,string"`
	ParentID int    `json:"parent_id,string,omitempty"`
	Type     string `json:"type"`
	TypeID   int    `json:"type_id,string"`
	Name     string `json:"name"`
	Creator  int    `json:"creator,string"`
	Modified int    `json:"modified,string"`
}

type FolderGetResponseContent struct {
	Folder     []Folder `json:"folder"`
	Files      []File   `json:"files"`
	Permission string   `json:"permission"`
}

type FolderGetResponsePayload struct {
	Content FolderGetResponseContent `json:"content"`
}

type FolderGetResponse struct {
	Status    Status                   `json:"status"`
	Payload   FolderGetResponsePayload `json:"payload"`
	Signature string                   `json:"signature"`
}

func (api *Client) GetFolderContent(ch ChannelInfo, fID, limit, offset int) (FolderGetResponseContent, error) {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("folder_id", fmt.Sprintf("%d", fID))
	v.Set("type", "channel") // TODO: add possibility to query conversations as well
	v.Set("type_id", fmt.Sprintf("%d", ch.ID))
	v.Set("folder_only", "no")
	v.Set("offset", fmt.Sprintf("%d", offset))
	v.Set("limit", fmt.Sprintf("%d", limit))
	v.Set("search", "")
	v.Set("sorting", "name_asc")

	response := FolderGetResponse{}

	err := api.postMethod("folder/get", v, &response)
	if err != nil {
		return FolderGetResponseContent{}, err
	}

	return response.Payload.Content, nil
}
