package v1

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/util/intstr"

	v1 "github.com/openshift/api/apps/v1"
	"github.com/openshift/library-go/pkg/image/imageutil"
	newer "github.com/openshift/openshift-apiserver/pkg/apps/apis/apps"
)

func Convert_v1_DeploymentTriggerImageChangeParams_To_apps_DeploymentTriggerImageChangeParams(in *v1.DeploymentTriggerImageChangeParams, out *newer.DeploymentTriggerImageChangeParams, s conversion.Scope) error {
	if err := autoConvert_v1_DeploymentTriggerImageChangeParams_To_apps_DeploymentTriggerImageChangeParams(in, out, s); err != nil {
		return err
	}
	switch in.From.Kind {
	case "ImageStreamTag":
	case "ImageStream", "ImageRepository":
		out.From.Kind = "ImageStreamTag"
		if !strings.Contains(out.From.Name, ":") {
			out.From.Name = imageutil.JoinImageStreamTag(out.From.Name, imageutil.DefaultImageTag)
		}
	default:
		// Will be handled by validation
	}
	return nil
}

func Convert_apps_DeploymentTriggerImageChangeParams_To_v1_DeploymentTriggerImageChangeParams(in *newer.DeploymentTriggerImageChangeParams, out *v1.DeploymentTriggerImageChangeParams, s conversion.Scope) error {
	if err := autoConvert_apps_DeploymentTriggerImageChangeParams_To_v1_DeploymentTriggerImageChangeParams(in, out, s); err != nil {
		return err
	}
	switch in.From.Kind {
	case "ImageStreamTag":
	case "ImageStream", "ImageRepository":
		out.From.Kind = "ImageStreamTag"
		if !strings.Contains(out.From.Name, ":") {
			out.From.Name = imageutil.JoinImageStreamTag(out.From.Name, imageutil.DefaultImageTag)
		}
	default:
		// Will be handled by validation
	}
	return nil
}

func Convert_v1_RollingDeploymentStrategyParams_To_apps_RollingDeploymentStrategyParams(in *v1.RollingDeploymentStrategyParams, out *newer.RollingDeploymentStrategyParams, s conversion.Scope) error {
	SetDefaults_RollingDeploymentStrategyParams(in)

	out.UpdatePeriodSeconds = in.UpdatePeriodSeconds
	out.IntervalSeconds = in.IntervalSeconds
	out.TimeoutSeconds = in.TimeoutSeconds

	if in.Pre != nil {
		out.Pre = &newer.LifecycleHook{}
		if err := Convert_v1_LifecycleHook_To_apps_LifecycleHook(in.Pre, out.Pre, s); err != nil {
			return err
		}
	}
	if in.Post != nil {
		out.Post = &newer.LifecycleHook{}
		if err := Convert_v1_LifecycleHook_To_apps_LifecycleHook(in.Post, out.Post, s); err != nil {
			return err
		}
	}
	if in.MaxUnavailable != nil {
		if err := s.Convert(in.MaxUnavailable, &out.MaxUnavailable, 0); err != nil {
			return err
		}
	}
	if in.MaxSurge != nil {
		if err := s.Convert(in.MaxSurge, &out.MaxSurge, 0); err != nil {
			return err
		}
	}
	return nil
}

func Convert_apps_RollingDeploymentStrategyParams_To_v1_RollingDeploymentStrategyParams(in *newer.RollingDeploymentStrategyParams, out *v1.RollingDeploymentStrategyParams, s conversion.Scope) error {
	out.UpdatePeriodSeconds = in.UpdatePeriodSeconds
	out.IntervalSeconds = in.IntervalSeconds
	out.TimeoutSeconds = in.TimeoutSeconds

	if in.Pre != nil {
		out.Pre = &v1.LifecycleHook{}
		if err := Convert_apps_LifecycleHook_To_v1_LifecycleHook(in.Pre, out.Pre, s); err != nil {
			return err
		}
	}
	if in.Post != nil {
		out.Post = &v1.LifecycleHook{}
		if err := Convert_apps_LifecycleHook_To_v1_LifecycleHook(in.Post, out.Post, s); err != nil {
			return err
		}
	}

	if out.MaxUnavailable == nil {
		out.MaxUnavailable = &intstr.IntOrString{}
	}
	if out.MaxSurge == nil {
		out.MaxSurge = &intstr.IntOrString{}
	}

	if err := metav1.Convert_intstr_IntOrString_To_intstr_IntOrString(&in.MaxUnavailable, out.MaxUnavailable, nil); err != nil {
		return err
	}
	if err := metav1.Convert_intstr_IntOrString_To_intstr_IntOrString(&in.MaxSurge, out.MaxSurge, nil); err != nil {
		return err
	}

	return nil
}
