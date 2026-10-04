package logs

import (
	"fmt"
	"os"
	"time"
)

type TimestompRequest struct {
	Path       string
	AccessTime *time.Time
	ModTime    *time.Time
	CloneFrom  string // copy timestamps from this file
	DryRun     bool
}

type TimestompResult struct {
	Path          string
	OriginalAtime time.Time
	OriginalMtime time.Time
	NewAtime      time.Time
	NewMtime      time.Time
	Applied       bool
	DryRun        bool
	Error         string
}

func Timestomp(req TimestompRequest) TimestompResult {
	result := TimestompResult{
		Path:   req.Path,
		DryRun: req.DryRun,
	}

	info, err := os.Stat(req.Path)
	if err != nil {
		result.Error = fmt.Sprintf("cannot access target: %v", err)
		return result
	}

	result.OriginalMtime = info.ModTime()
	result.OriginalAtime = info.ModTime()

	newAtime := info.ModTime()
	newMtime := info.ModTime()

	if req.CloneFrom != "" {
		srcInfo, err := os.Stat(req.CloneFrom)
		if err != nil {
			result.Error = fmt.Sprintf("cannot access source: %v", err)
			return result
		}
		newAtime = srcInfo.ModTime()
		newMtime = srcInfo.ModTime()
	} else {
		if req.AccessTime != nil {
			newAtime = *req.AccessTime
		}
		if req.ModTime != nil {
			newMtime = *req.ModTime
		}
	}

	result.NewAtime = newAtime
	result.NewMtime = newMtime

	if req.DryRun {
		return result
	}

	if err := os.Chtimes(req.Path, newAtime, newMtime); err != nil {
		result.Error = fmt.Sprintf("failed to change timestamps: %v", err)
		return result
	}

	result.Applied = true
	return result
}
