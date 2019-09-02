package internalversion

import (
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kprinters "k8s.io/kubernetes/pkg/printers"

	projectv1 "github.com/openshift/api/project/v1"
	oapi "github.com/openshift/openshift-apiserver/pkg/api"
	projectapi "github.com/openshift/openshift-apiserver/pkg/project/apis/project"
)

func AddProjectOpenShiftHandlers(h kprinters.PrintHandler) {
	projectColumnDefinitions := []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: metav1.ObjectMeta{}.SwaggerDoc()["name"]},
		{Name: "Display Name", Type: "string", Description: "The name displayed by a UI when referencing a project."},
		{Name: "Status", Type: "string", Description: projectv1.ProjectStatus{}.SwaggerDoc()["phase"]},
	}
	if err := h.TableHandler(projectColumnDefinitions, printProjectList); err != nil {
		panic(err)
	}
	if err := h.TableHandler(projectColumnDefinitions, printProject); err != nil {
		panic(err)
	}
}

func printProject(project *projectapi.Project, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	row := metav1.TableRow{
		Object: runtime.RawExtension{Object: project},
	}

	name := formatResourceName(options.Kind, project.Name, options.WithKind)

	row.Cells = append(row.Cells, name, project.Annotations[oapi.OpenShiftDisplayName], project.Status.Phase)

	return []metav1.TableRow{row}, nil
}

func printProjectList(list *projectapi.ProjectList, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	sort.Sort(SortableProjects(list.Items))
	rows := make([]metav1.TableRow, 0, len(list.Items))
	for i := range list.Items {
		r, err := printProject(&list.Items[i], options)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r...)
	}
	return rows, nil
}

// SortableProjects is a list of projects that can be sorted
type SortableProjects []projectapi.Project

func (list SortableProjects) Len() int {
	return len(list)
}

func (list SortableProjects) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

func (list SortableProjects) Less(i, j int) bool {
	return list[i].ObjectMeta.Name < list[j].ObjectMeta.Name
}

// formatResourceName receives a resource kind, name, and boolean specifying
// whether or not to update the current name to "kind/name"
func formatResourceName(kind schema.GroupKind, name string, withKind bool) string {
	if !withKind || kind.Empty() {
		return name
	}

	return strings.ToLower(kind.String()) + "/" + name
}
