package internalversion

import (
	"fmt"
	"strings"
	"time"

	units "github.com/docker/go-units"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kprinters "k8s.io/kubernetes/pkg/printers"

	imagev1 "github.com/openshift/api/image/v1"
	imageapi "github.com/openshift/openshift-apiserver/pkg/image/apis/image"
)

func AddImageOpenShiftHandlers(h kprinters.PrintHandler) {
	imageColumnDefinitions := []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: metav1.ObjectMeta{}.SwaggerDoc()["name"]},
		{Name: "Image Reference", Type: "string", Description: imagev1.Image{}.SwaggerDoc()["dockerImageReference"]},
	}
	if err := h.TableHandler(imageColumnDefinitions, printImageList); err != nil {
		panic(err)
	}
	if err := h.TableHandler(imageColumnDefinitions, printImage); err != nil {
		panic(err)
	}

	imageStreamColumnDefinitions := []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: metav1.ObjectMeta{}.SwaggerDoc()["name"]},
		{Name: "Image Repository", Type: "string", Description: imagev1.ImageStreamStatus{}.SwaggerDoc()["dockerImageRepository"]},
		{Name: "Tags", Type: "string", Description: "Human readable list of tags."},
		{Name: "Updated", Type: "string", Description: "Last update time."},
	}
	if err := h.TableHandler(imageStreamColumnDefinitions, printImageStreamList); err != nil {
		panic(err)
	}
	if err := h.TableHandler(imageStreamColumnDefinitions, printImageStream); err != nil {
		panic(err)
	}

	imageStreamTagColumnDefinitions := []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: metav1.ObjectMeta{}.SwaggerDoc()["name"]},
		{Name: "Image Reference", Type: "string", Description: imagev1.Image{}.SwaggerDoc()["dockerImageReference"]},
		{Name: "Updated", Type: "string", Description: "Last update time."},
		{Name: "Image Name", Type: "string", Priority: 1, Description: imagev1.ImageStreamTag{}.SwaggerDoc()["image"]},
	}
	if err := h.TableHandler(imageStreamTagColumnDefinitions, printImageStreamTagList); err != nil {
		panic(err)
	}
	if err := h.TableHandler(imageStreamTagColumnDefinitions, printImageStreamTag); err != nil {
		panic(err)
	}

	imageStreamImageColumnDefinitions := []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: metav1.ObjectMeta{}.SwaggerDoc()["name"]},
		{Name: "Updated", Type: "string", Description: "Last update time."},
		{Name: "Image Reference", Type: "string", Priority: 1, Description: imagev1.Image{}.SwaggerDoc()["dockerImageReference"]},
		{Name: "Image Name", Type: "string", Priority: 1, Description: imagev1.ImageStreamImage{}.SwaggerDoc()["image"]},
	}
	if err := h.TableHandler(imageStreamImageColumnDefinitions, printImageStreamImage); err != nil {
		panic(err)
	}
}

func printImage(image *imageapi.Image, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	row := metav1.TableRow{
		Object: runtime.RawExtension{Object: image},
	}

	name := formatResourceName(options.Kind, image.Name, options.WithKind)
	row.Cells = append(row.Cells, name, image.DockerImageReference)

	return []metav1.TableRow{row}, nil
}

func printImageList(list *imageapi.ImageList, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	rows := make([]metav1.TableRow, 0, len(list.Items))
	for i := range list.Items {
		r, err := printImage(&list.Items[i], options)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r...)
	}
	return rows, nil
}

func printImageStream(stream *imageapi.ImageStream, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	row := metav1.TableRow{
		Object: runtime.RawExtension{Object: stream},
	}

	name := formatResourceName(options.Kind, stream.Name, options.WithKind)

	var latest metav1.Time
	for _, list := range stream.Status.Tags {
		if len(list.Items) > 0 {
			if list.Items[0].Created.After(latest.Time) {
				latest = list.Items[0].Created
			}
		}
	}
	latestTime := ""
	if !latest.IsZero() {
		latestTime = fmt.Sprintf("%s ago", formatRelativeTime(latest.Time))
	}

	tags := printTagsUpToWidth(stream.Status.Tags, 40)

	repo := stream.Spec.DockerImageRepository
	if len(repo) == 0 {
		repo = stream.Status.DockerImageRepository
	}
	if len(stream.Status.PublicDockerImageRepository) > 0 {
		repo = stream.Status.PublicDockerImageRepository
	}

	row.Cells = append(row.Cells, name, repo, tags, latestTime)

	return []metav1.TableRow{row}, nil
}

func printImageStreamList(list *imageapi.ImageStreamList, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	rows := make([]metav1.TableRow, 0, len(list.Items))
	for i := range list.Items {
		r, err := printImageStream(&list.Items[i], options)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r...)
	}
	return rows, nil
}

func printImageStreamTag(ist *imageapi.ImageStreamTag, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	row := metav1.TableRow{
		Object: runtime.RawExtension{Object: ist},
	}

	name := formatResourceName(options.Kind, ist.Name, options.WithKind)
	created := fmt.Sprintf("%s ago", formatRelativeTime(ist.CreationTimestamp.Time))

	row.Cells = append(row.Cells, name, ist.Image.DockerImageReference, created)

	if options.Wide {
		row.Cells = append(row.Cells, ist.Image.Name)
	}

	return []metav1.TableRow{row}, nil
}

func printImageStreamTagList(list *imageapi.ImageStreamTagList, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	rows := make([]metav1.TableRow, 0, len(list.Items))
	for i := range list.Items {
		r, err := printImageStreamTag(&list.Items[i], options)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r...)
	}
	return rows, nil
}

func printImageStreamImage(isi *imageapi.ImageStreamImage, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	row := metav1.TableRow{
		Object: runtime.RawExtension{Object: isi},
	}

	name := formatResourceName(options.Kind, isi.Name, options.WithKind)
	created := fmt.Sprintf("%s ago", formatRelativeTime(isi.CreationTimestamp.Time))

	row.Cells = append(row.Cells, name, created)

	if options.Wide {
		row.Cells = append(row.Cells, isi.Image.DockerImageReference, isi.Image.Name)
	}

	return []metav1.TableRow{row}, nil
}

// printTagsUpToWidth displays a human readable list of tags with as many tags as will fit in the
// width we budget. It will always display at least one tag, and will allow a slightly wider width
// if it's less than 25% of the total width to feel more even.
func printTagsUpToWidth(statusTags map[string]imageapi.TagEventList, preferredWidth int) string {
	tags := imageapi.SortStatusTags(statusTags)
	remaining := preferredWidth
	for i, tag := range tags {
		remaining -= len(tag) + 1
		if remaining >= 0 {
			continue
		}
		if i == 0 {
			tags = tags[:1]
			break
		}
		// if we've left more than 25% of the width unfilled, and adding the current tag would be
		// less than 125% of the preferred width, keep going in order to make the edges less ragged.
		margin := preferredWidth / 4
		if margin < (remaining+len(tag)) && margin >= (-remaining) {
			continue
		}
		tags = tags[:i]
		break
	}
	if hiddenTags := len(statusTags) - len(tags); hiddenTags > 0 {
		return fmt.Sprintf("%s + %d more...", strings.Join(tags, ","), hiddenTags)
	}
	return strings.Join(tags, ",")
}

// formatResourceName receives a resource kind, name, and boolean specifying
// whether or not to update the current name to "kind/name"
func formatResourceName(kind schema.GroupKind, name string, withKind bool) string {
	if !withKind || kind.Empty() {
		return name
	}

	return strings.ToLower(kind.String()) + "/" + name
}

func formatRelativeTime(t time.Time) string {
	return units.HumanDuration(timeNowFn().Sub(t))
}

var timeNowFn = func() time.Time {
	return time.Now()
}
