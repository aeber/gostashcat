package gostashcat

import (
	"fmt"
	"net/url"
	"strconv"
)

type ManageUser struct {
	ID               string `json:"id"`
	FirstName        string `json:"first_name"`
	LastName         string `json:"last_name"`
	Tag              string `json:"tag"`
	Email            bool   `json:"email"`
	TimeJoined       string `json:"time_joined"`
	MembershipExpiry string `json:"membership_expiry,omitempty"`
	Deactivated      string `json:"deactivated,omitempty"`
	Active           string `json:"active,omitempty"`
	LastLogin        int    `json:"last_login,omitempty"`
	Image            string `json:"image,omitempty"`
	AllowsVoipCalls  bool   `json:"allows_voip_calls,omitempty"`
}

type ManageUsersListingResponsePayload struct {
	TotalRecords int    `json:"num_total_records"`
	Users        []User `json:"users"`
}

type ManageUsersListingResponse struct {
	Status    Status                            `json:"status"`
	Payload   ManageUsersListingResponsePayload `json:"payload"`
	Signature string                            `json:"signature"`
}

func (api *Client) ManageListUsers(limit int, offset int, search string, companyID string) ([]User, error) {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("company_id", companyID)
	v.Set("limit", fmt.Sprintf("%d", limit))
	v.Set("offset", fmt.Sprintf("%d", offset))
	if search != "" {
		v.Set("search", search)
	}
	v.Set("sorting", "[\"id_asc\"]")
	v.Set("group_ids", "[]")
	v.Set("withkey", strconv.FormatBool(false))
	v.Set("not_member_of_any_group", strconv.FormatBool(false))

	response := ManageUsersListingResponse{}

	err := api.postMethod("manage/list_users", v, &response)
	if err != nil {
		return nil, err
	}

	return response.Payload.Users, nil
}
