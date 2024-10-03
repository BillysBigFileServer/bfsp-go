package usage

import (
	"context"
	"fmt"

	"github.com/BillysBigFileServer/bfsp-go"
)

type Usage struct {
	TotalUsage uint64
	StorageCap uint64
}

func GetUsage(ctx context.Context) (*Usage, error) {
	client := bfsp.ClientFromContext(ctx)
	query := bfsp.FileServerMessage_GetUsageQuery_{
		GetUsageQuery: &bfsp.FileServerMessage_GetUsageQuery{},
	}

	resp := bfsp.GetUsageResp{}
	if err := client.SendFileServerMessage(&query, &resp); err != nil {
		return nil, err
	}

	switch resp.Response.(type) {
	case *bfsp.GetUsageResp_Usage_:
		usage := resp.Response.(*bfsp.GetUsageResp_Usage_)
		return &Usage{
			TotalUsage: usage.Usage.TotalUsage,
			StorageCap: usage.Usage.StorageCap,
		}, nil
	case *bfsp.GetUsageResp_Err:
		err := resp.Response.(*bfsp.GetUsageResp_Err)
		return nil, fmt.Errorf("%s", err.Err)
	default:
		return nil, fmt.Errorf("unhandled GetUsageResp type")
	}
}
