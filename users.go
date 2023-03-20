package gostashcat

import (
	"fmt"
	"net/url"
	"strconv"
)

type User struct {
	ID              string `json:"id"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	SocketID        string `json:"socket_id,omitempty"`
	Online          bool   `json:"online"`
	Active          string `json:"active,omitempty"`
	Deleted         string `json:"deleted,omitempty"`
	AllowsVoipCalls bool   `json:"allows_voip_calls,omitempty"`
	Tag             string `json:"tag,omitempty"`
	PublicKey       string `json:"public_key"`
	Roles           []Role `json:"roles"`
}

type UsersListingResponsePayload struct {
	Users []User `json:"users"`
}

type UsersListingResponse struct {
	Status    Status                      `json:"status"`
	Payload   UsersListingResponsePayload `json:"payload"`
	Signature string                      `json:"signature"`
}

type UserListingResponsePayload struct {
	User User `json:"user"`
}

type UserInfoResponse struct {
	Status    Status                     `json:"status"`
	Payload   UserListingResponsePayload `json:"payload"`
	Signature string                     `json:"signature"`
}

func (api *Client) ListUsers(limit int, offset int, search string) ([]User, error) {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("limit", fmt.Sprintf("%d", limit))
	v.Set("offset", fmt.Sprintf("%d", offset))
	if search != "" {
		v.Set("search", search)
	}
	v.Set("key_hashes", strconv.FormatBool(false))
	v.Set("sorting", "[\"first_name_asc\", \"last_name_asc\"]")
	v.Set("exclude_user_ids", "["+api.UserInfo.ID+"]") // Exclude self from search
	v.Set("group_ids", "[]")

	response := UsersListingResponse{}

	err := api.postMethod("users/listing", v, &response)
	if err != nil {
		return nil, err
	}

	return response.Payload.Users, nil
}

func (api *Client) GetUserMe() (User, error) {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("withkey", strconv.FormatBool(false))

	response := UserInfoResponse{}

	err := api.postMethod("users/me", v, &response)
	if err != nil {
		return User{}, err
	}

	return response.Payload.User, nil
}

func (api *Client) GetUserInfo(userID int) (User, error) {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("user_id", fmt.Sprintf("%d", userID))
	v.Set("withkey", strconv.FormatBool(true))

	response := UserInfoResponse{}

	err := api.postMethod("users/info", v, &response)
	if err != nil {
		return User{}, err
	}

	return response.Payload.User, nil
}
