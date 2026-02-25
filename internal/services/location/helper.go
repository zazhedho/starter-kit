package servicelocation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	domainlocation "starter-kit/internal/domain/location"
)

func fetchResponseBody(url, entity string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", entity, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

func unmarshalLocationMap(body []byte) (map[string]string, error) {
	var dataMap map[string]string
	if err := json.Unmarshal(body, &dataMap); err != nil {
		return nil, err
	}

	return dataMap, nil
}

func toSortedLocations(dataMap map[string]string) []domainlocation.Location {
	locations := make([]domainlocation.Location, 0, len(dataMap))
	for code, name := range dataMap {
		locations = append(locations, domainlocation.Location{
			Code: code,
			Name: name,
		})
	}

	sort.Slice(locations, func(i, j int) bool {
		return locations[i].Name < locations[j].Name
	})

	return locations
}
