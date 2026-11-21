package env

import "os"

// DataDirKey names the variable that overrides the data root.
const DataDirKey = "CLOUD_DATA_DIR"

// DataDirDefault is the on-disk data root when DataDirKey is unset.
const DataDirDefault = "/var/lib/cloud"

// DataDir returns the data root this process must use.
//
// It is stated once so that the light router can agree with the request tier
// about WHERE the volume is without linking it. That agreement is load bearing:
// the router takes the pod's writer lease on a lock file under this path and the
// children open their stores under it, so a second definition that drifted by one
// directory would put the lock somewhere nothing else consults — an interlock
// guarding an empty folder.
func DataDir() string {
	if v := os.Getenv(DataDirKey); v != "" {
		return v
	}
	return DataDirDefault
}
