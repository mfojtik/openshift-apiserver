package internalversion

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kprinters "k8s.io/kubernetes/pkg/printers"

	templatev1 "github.com/openshift/api/template/v1"

	templateapi "github.com/openshift/openshift-apiserver/pkg/template/apis/template"
)

func AddTemplateOpenShiftHandler(h kprinters.PrintHandler) {
	addTemplateInstance(h)
	addBrokerTemplateInstance(h)
}

func addBrokerTemplateInstance(h kprinters.PrintHandler) {
	brokerTemplateInstanceColumnsDefinitions := []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: metav1.ObjectMeta{}.SwaggerDoc()["name"]},
		{Name: "Template Instance", Type: "string", Description: metav1.ObjectMeta{}.SwaggerDoc()["name"]},
	}
	if err := h.TableHandler(brokerTemplateInstanceColumnsDefinitions, printBrokerTemplateInstance); err != nil {
		panic(err)
	}
	if err := h.TableHandler(brokerTemplateInstanceColumnsDefinitions, printBrokerTemplateInstanceList); err != nil {
		panic(err)
	}
}

func printBrokerTemplateInstance(brokerTemplateInstance *templateapi.BrokerTemplateInstance, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	row := metav1.TableRow{
		Object: runtime.RawExtension{Object: brokerTemplateInstance},
	}

	brokerTemplateInstanceName := brokerTemplateInstance.Name
	if options.WithNamespace {
		brokerTemplateInstanceName = fmt.Sprintf("%s/%s", brokerTemplateInstance.Namespace, brokerTemplateInstance.Name)
	}

	row.Cells = append(row.Cells,
		brokerTemplateInstanceName,
		fmt.Sprintf("%s/%s", brokerTemplateInstance.Spec.TemplateInstance.Namespace, brokerTemplateInstance.Spec.TemplateInstance.Name),
	)

	return []metav1.TableRow{row}, nil
}

func printBrokerTemplateInstanceList(brokerTemplateInstanceList *templateapi.BrokerTemplateInstanceList, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	rows := make([]metav1.TableRow, 0, len(brokerTemplateInstanceList.Items))
	for i := range brokerTemplateInstanceList.Items {
		r, err := printBrokerTemplateInstance(&brokerTemplateInstanceList.Items[i], options)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r...)
	}
	return rows, nil
}

func addTemplateInstance(h kprinters.PrintHandler) {
	templateInstanceColumnsDefinitions := []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: metav1.ObjectMeta{}.SwaggerDoc()["name"]},
		{Name: "Template", Type: "string", Format: "name", Description: templatev1.Template{}.SwaggerDoc()["name"]},
	}
	if err := h.TableHandler(templateInstanceColumnsDefinitions, printTemplateInstance); err != nil {
		panic(err)
	}
	if err := h.TableHandler(templateInstanceColumnsDefinitions, printTemplateInstanceList); err != nil {
		panic(err)
	}
}

func printTemplateInstance(templateInstance *templateapi.TemplateInstance, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	row := metav1.TableRow{
		Object: runtime.RawExtension{Object: templateInstance},
	}

	templateInstanceName := templateInstance.Name
	if options.WithNamespace {
		templateInstanceName = fmt.Sprintf("%s/%s", templateInstance.Namespace, templateInstance.Name)
	}

	row.Cells = append(row.Cells,
		templateInstanceName,
		templateInstance.Spec.Template.Name,
	)

	return []metav1.TableRow{row}, nil
}

func printTemplateInstanceList(templateInstanceList *templateapi.TemplateInstanceList, options kprinters.PrintOptions) ([]metav1.TableRow, error) {
	rows := make([]metav1.TableRow, 0, len(templateInstanceList.Items))
	for i := range templateInstanceList.Items {
		r, err := printTemplateInstance(&templateInstanceList.Items[i], options)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r...)
	}
	return rows, nil
}
