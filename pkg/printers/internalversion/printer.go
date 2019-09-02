package internalversion

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	kapi "k8s.io/kubernetes/pkg/apis/core"
	kprinters "k8s.io/kubernetes/pkg/printers"
	kprintersinternal "k8s.io/kubernetes/pkg/printers/internalversion"

	oapi "github.com/openshift/openshift-apiserver/pkg/api"
	appsapi "github.com/openshift/openshift-apiserver/pkg/apps/apis/apps"
	authorizationapi "github.com/openshift/openshift-apiserver/pkg/authorization/apis/authorization"
	buildapi "github.com/openshift/openshift-apiserver/pkg/build/apis/build"
	buildinternalhelpers "github.com/openshift/openshift-apiserver/pkg/build/apis/build/internal_helpers"
	imageapi "github.com/openshift/openshift-apiserver/pkg/image/apis/image"
	oauthapi "github.com/openshift/openshift-apiserver/pkg/oauth/apis/oauth"
	projectapi "github.com/openshift/openshift-apiserver/pkg/project/apis/project"
	quotaapi "github.com/openshift/openshift-apiserver/pkg/quota/apis/quota"
	routeapi "github.com/openshift/openshift-apiserver/pkg/route/apis/route"
	securityapi "github.com/openshift/openshift-apiserver/pkg/security/apis/security"
	templateapi "github.com/openshift/openshift-apiserver/pkg/template/apis/template"
	userapi "github.com/openshift/openshift-apiserver/pkg/user/apis/user"
)

var (
	buildColumns                = []string{"Name", "Type", "From", "Status", "Started", "Duration"}
	buildConfigColumns          = []string{"Name", "Type", "From", "Latest"}
	imageColumns                = []string{"Name", "Image Reference"}
	imageStreamTagColumns       = []string{"Name", "Image Reference", "Updated"}
	imageStreamTagWideColumns   = []string{"Name", "Image Reference", "Updated", "Image Name"}
	imageStreamImageColumns     = []string{"Name", "Updated"}
	imageStreamImageWideColumns = []string{"Name", "Image Reference", "Updated", "Image Name"}
	imageStreamColumns          = []string{"Name", "Image Repository", "Tags", "Updated"}
	projectColumns              = []string{"Name", "Display Name", "Status"}
	routeColumns                = []string{"Name", "Host/Port", "Path", "Services", "Port", "Termination", "Wildcard"}
	deploymentConfigColumns     = []string{"Name", "Revision", "Desired", "Current", "Triggered By"}
	templateColumns             = []string{"Name", "Description", "Parameters", "Objects"}
	roleBindingColumns          = []string{"Name", "Role", "Users", "Groups", "Service Accounts", "Subjects"}
	roleColumns                 = []string{"Name"}

	oauthClientColumns              = []string{"Name", "Secret", "WWW-Challenge", "Token-Max-Age", "Redirect URIs"}
	oauthClientAuthorizationColumns = []string{"Name", "User Name", "Client Name", "Scopes"}
	oauthAccessTokenColumns         = []string{"Name", "User Name", "Client Name", "Created", "Expires", "Redirect URI", "Scopes"}
	oauthAuthorizeTokenColumns      = []string{"Name", "User Name", "Client Name", "Created", "Expires", "Redirect URI", "Scopes"}

	userColumns                = []string{"Name", "UID", "Full Name", "Identities"}
	identityColumns            = []string{"Name", "IDP Name", "IDP User Name", "User Name", "User UID"}
	userIdentityMappingColumns = []string{"Name", "Identity", "User Name", "User UID"}
	groupColumns               = []string{"Name", "Users"}

	// IsPersonalSubjectAccessReviewColumns contains known custom role extensions
	IsPersonalSubjectAccessReviewColumns = []string{"Name"}

	clusterResourceQuotaColumns = []string{"Name", "Label Selector", "Annotation Selector"}

	roleBindingRestrictionColumns = []string{"Name", "Subject Type", "Subjects"}

	templateInstanceColumns       = []string{"Name", "Template"}
	brokerTemplateInstanceColumns = []string{"Name", "Template Instance"}

	policyRuleColumns = []string{"Verbs", "Non-Resource URLs", "Resource Names", "API Groups", "Resources"}

	securityContextConstraintsColumns = []string{"Name", "Priv", "Caps", "SELinux", "RunAsUser", "FSGroup", "SupGroup", "Priority", "ReadyOnlyFS", "Volumes"}
	rangeAllocationColumns            = []string{"Name", "Range", "Data"}
)

func init() {
	// TODO this should be eliminated
	kprintersinternal.AddHandlers = func(p kprinters.PrintHandler) {
		kprintersinternal.AddKubeHandlers(p)
		AddHandlers(p)
	}
}

type originTableHandler struct {
	err            error
	printerHandler kprinters.PrintHandler
}

func newOriginTableHandler(p kprinters.PrintHandler) *originTableHandler {
	return &originTableHandler{printerHandler: p}
}

func (h *originTableHandler) add(columns []string, printFn interface{}, wideColumns ...string) {
	if h.err != nil {
		return
	}
	columnDefinition := []metav1.TableColumnDefinition{}
	for _, c := range columns {
		d := metav1.TableColumnDefinition{Name: c, Type: "string"}
		if c == "Name" {
			d.Description = metav1.ObjectMeta{}.SwaggerDoc()["name"]
		}
		columnDefinition = append(columnDefinition, d)
	}
	for _, c := range wideColumns {
		d := metav1.TableColumnDefinition{Name: c, Type: "string", Priority: 1}
		columnDefinition = append(columnDefinition, d)
	}
	if err := h.printerHandler.TableHandler(columnDefinition, printFn); err != nil {
		h.err = err
	}
}

// AddHandlers adds print handlers for internal openshift API objects
func AddHandlers(p kprinters.PrintHandler) {
	h := newOriginTableHandler(p)
	defer func() {
		if h.err != nil {
			panic(h.err)
		}
	}()

	h.add(buildColumns, printBuild)
	h.add(buildConfigColumns, printBuildConfig)
	h.add(buildConfigColumns, printBuildConfigList)
	h.add(policyRuleColumns, printSubjectRulesReview)
	h.add(policyRuleColumns, printSelfSubjectRulesReview)
	h.add(imageColumns, printImage)
	h.add(imageStreamTagColumns, printImageStreamTag, imageStreamImageWideColumns...)
	h.add(imageStreamTagColumns, printImageStreamTagList, imageStreamTagWideColumns...)
	h.add(imageStreamImageColumns, printImageStreamImage, imageStreamImageWideColumns...)
	h.add(imageColumns, printImageList)
	h.add(imageStreamColumns, printImageStream)
	h.add(imageStreamColumns, printImageStreamList)
	h.add(projectColumns, printProject)
	h.add(projectColumns, printProjectList)
	h.add(routeColumns, printRoute)
	h.add(routeColumns, printRouteList)
	h.add(deploymentConfigColumns, printDeploymentConfig)
	h.add(deploymentConfigColumns, printDeploymentConfigList)
	h.add(templateColumns, printTemplate)
	h.add(templateColumns, printTemplateList)

	h.add(roleBindingColumns, printRoleBinding)
	h.add(roleBindingColumns, printRoleBindingList)
	h.add(roleColumns, printRole)
	h.add(roleColumns, printRoleList)

	h.add(roleColumns, printClusterRole)
	h.add(roleColumns, printClusterRoleList)
	h.add(roleBindingColumns, printClusterRoleBinding)
	h.add(roleBindingColumns, printClusterRoleBindingList)

	h.add(oauthClientColumns, printOAuthClient)
	h.add(oauthClientColumns, printOAuthClientList)
	h.add(oauthClientAuthorizationColumns, printOAuthClientAuthorization)
	h.add(oauthClientAuthorizationColumns, printOAuthClientAuthorizationList)
	h.add(oauthAccessTokenColumns, printOAuthAccessToken)
	h.add(oauthAccessTokenColumns, printOAuthAccessTokenList)
	h.add(oauthAuthorizeTokenColumns, printOAuthAuthorizeToken)
	h.add(oauthAuthorizeTokenColumns, printOAuthAuthorizeTokenList)

	h.add(userColumns, printUser)
	h.add(userColumns, printUserList)
	h.add(identityColumns, printIdentity)
	h.add(identityColumns, printIdentityList)
	h.add(userIdentityMappingColumns, printUserIdentityMapping)
	h.add(groupColumns, printGroup)
	h.add(groupColumns, printGroupList)

	h.add(IsPersonalSubjectAccessReviewColumns, printIsPersonalSubjectAccessReview)

	h.add(clusterResourceQuotaColumns, printClusterResourceQuota)
	h.add(clusterResourceQuotaColumns, printClusterResourceQuotaList)
	h.add(clusterResourceQuotaColumns, printAppliedClusterResourceQuota)
	h.add(clusterResourceQuotaColumns, printAppliedClusterResourceQuotaList)

	h.add(roleBindingRestrictionColumns, printRoleBindingRestriction)
	h.add(roleBindingRestrictionColumns, printRoleBindingRestrictionList)

	h.add(templateInstanceColumns, printTemplateInstance)
	h.add(templateInstanceColumns, printTemplateInstanceList)
	h.add(brokerTemplateInstanceColumns, printBrokerTemplateInstance)
	h.add(brokerTemplateInstanceColumns, printBrokerTemplateInstanceList)

	h.add(securityContextConstraintsColumns, printSecurityContextConstraints)
	h.add(securityContextConstraintsColumns, printSecurityContextConstraintsList)
	h.add(rangeAllocationColumns, printRangeAllocation)
	h.add(rangeAllocationColumns, printRangeAllocationList)
}

const templateDescriptionLen = 80

// formatResourceName receives a resource kind, name, and boolean specifying
// whether or not to update the current name to "kind/name"
func formatResourceName(kind schema.GroupKind, name string, withKind bool) string {
	if !withKind || kind.Empty() {
		return name
	}

	return strings.ToLower(kind.String()) + "/" + name
}

func printTemplate(t *templateapi.Template, w io.Writer, opts kprinters.PrintOptions) error {
	description := ""
	if t.Annotations != nil {
		description = t.Annotations["description"]
	}
	// Only print the first line of description
	if lines := strings.SplitN(description, "\n", 2); len(lines) > 1 {
		description = lines[0] + "..."
	}
	if len(description) > templateDescriptionLen {
		description = strings.TrimSpace(description[:templateDescriptionLen-3]) + "..."
	}
	empty, generated, total := 0, 0, len(t.Parameters)
	for _, p := range t.Parameters {
		if len(p.Value) > 0 {
			continue
		}
		if len(p.Generate) > 0 {
			generated++
			continue
		}
		empty++
	}
	params := ""
	switch {
	case empty > 0:
		params = fmt.Sprintf("%d (%d blank)", total, empty)
	case generated > 0:
		params = fmt.Sprintf("%d (%d generated)", total, generated)
	default:
		params = fmt.Sprintf("%d (all set)", total)
	}

	name := formatResourceName(opts.Kind, t.Name, opts.WithKind)

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", t.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%d", name, description, params, len(t.Objects)); err != nil {
		return err
	}
	if err := appendItemLabels(t.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printTemplateList(list *templateapi.TemplateList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, t := range list.Items {
		if err := printTemplate(&t, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printBuild(build *buildapi.Build, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, build.Name, opts.WithKind)

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", build.Namespace); err != nil {
			return err
		}
	}
	var created string
	if build.Status.StartTimestamp != nil {
		created = fmt.Sprintf("%s ago", formatRelativeTime(build.Status.StartTimestamp.Time))
	}
	var duration string
	if build.Status.Duration > 0 {
		duration = build.Status.Duration.String()
	}
	from := describeSourceShort(build.Spec.CommonSpec)
	status := string(build.Status.Phase)
	if len(build.Status.Reason) > 0 {
		status = fmt.Sprintf("%s (%s)", status, build.Status.Reason)
	}
	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s", name, buildinternalhelpers.StrategyType(build.Spec.Strategy), from, status, created,
		duration); err != nil {
		return err
	}
	if err := appendItemLabels(build.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func describeSourceShort(spec buildapi.CommonSpec) string {
	var from string
	switch source := spec.Source; {
	case source.Binary != nil:
		from = "Binary"
		if rev := describeSourceGitRevision(spec); len(rev) != 0 {
			from = fmt.Sprintf("%s@%s", from, rev)
		}
	case source.Dockerfile != nil && source.Git != nil:
		from = "Dockerfile,Git"
		if rev := describeSourceGitRevision(spec); len(rev) != 0 {
			from = fmt.Sprintf("%s@%s", from, rev)
		}
	case source.Dockerfile != nil:
		from = "Dockerfile"
	case source.Git != nil:
		from = "Git"
		if rev := describeSourceGitRevision(spec); len(rev) != 0 {
			from = fmt.Sprintf("%s@%s", from, rev)
		}
	default:
		from = buildSourceType(source)
	}
	return from
}

func buildSourceType(source buildapi.BuildSource) string {
	var sourceType string
	if source.Git != nil {
		sourceType = "Git"
	}
	if source.Dockerfile != nil {
		if len(sourceType) != 0 {
			sourceType = sourceType + ","
		}
		sourceType = sourceType + "Dockerfile"
	}
	if source.Binary != nil {
		if len(sourceType) != 0 {
			sourceType = sourceType + ","
		}
		sourceType = sourceType + "Binary"
	}
	return sourceType
}

var nonCommitRev = regexp.MustCompile("[^a-fA-F0-9]")

func describeSourceGitRevision(spec buildapi.CommonSpec) string {
	var rev string
	if spec.Revision != nil && spec.Revision.Git != nil {
		rev = spec.Revision.Git.Commit
	}
	if len(rev) == 0 && spec.Source.Git != nil {
		rev = spec.Source.Git.Ref
	}
	// if this appears to be a full Git commit hash, shorten it to 7 characters for brevity
	if !nonCommitRev.MatchString(rev) && len(rev) > 20 {
		rev = rev[:7]
	}
	return rev
}

func printBuildList(buildList *buildapi.BuildList, w io.Writer, opts kprinters.PrintOptions) error {
	builds := buildList.Items
	sort.Sort(buildinternalhelpers.BuildSliceByCreationTimestamp(builds))
	for _, build := range builds {
		if err := printBuild(&build, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printBuildConfig(bc *buildapi.BuildConfig, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, bc.Name, opts.WithKind)
	from := describeSourceShort(bc.Spec.CommonSpec)

	if bc.Spec.Strategy.CustomStrategy != nil {
		if opts.WithNamespace {
			if _, err := fmt.Fprintf(w, "%s\t", bc.Namespace); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(w, "%s\t%v\t%s\t%d\n", name, buildinternalhelpers.StrategyType(bc.Spec.Strategy),
			bc.Spec.Strategy.CustomStrategy.From.Name, bc.Status.LastVersion)
		return err
	}
	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", bc.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%v\t%s\t%d", name, buildinternalhelpers.StrategyType(bc.Spec.Strategy), from,
		bc.Status.LastVersion); err != nil {
		return err
	}
	if err := appendItemLabels(bc.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printSubjectRulesReview(rulesReview *authorizationapi.SubjectRulesReview, w io.Writer, opts kprinters.PrintOptions) error {
	printPolicyRule(rulesReview.Status.Rules, w)
	return nil
}

func printSelfSubjectRulesReview(selfSubjectRulesReview *authorizationapi.SelfSubjectRulesReview, w io.Writer, opts kprinters.PrintOptions) error {
	printPolicyRule(selfSubjectRulesReview.Status.Rules, w)
	return nil
}

func printPolicyRule(policyRules []authorizationapi.PolicyRule, w io.Writer) error {
	for _, rule := range policyRules {
		fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%v\n",
			rule.Verbs.List(),
			rule.NonResourceURLs.List(),
			rule.ResourceNames.List(),
			rule.APIGroups,
			rule.Resources.List(),
		)
	}
	return nil
}

func printBuildConfigList(buildList *buildapi.BuildConfigList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, buildConfig := range buildList.Items {
		if err := printBuildConfig(&buildConfig, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printImage(image *imageapi.Image, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, image.Name, opts.WithKind)

	if _, err := fmt.Fprintf(w, "%s\t%s", name, image.DockerImageReference); err != nil {
		return err
	}
	if err := appendItemLabels(image.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printImageStreamTag(ist *imageapi.ImageStreamTag, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, ist.Name, opts.WithKind)
	created := fmt.Sprintf("%s ago", formatRelativeTime(ist.CreationTimestamp.Time))

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", ist.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%s\t%s", name, ist.Image.DockerImageReference, created); err != nil {
		return err
	}
	if opts.Wide {
		if _, err := fmt.Fprintf(w, "\t%s", ist.Image.Name); err != nil {
			return err
		}
	}
	if err := appendItemLabels(ist.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printImageStreamTagList(list *imageapi.ImageStreamTagList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, ist := range list.Items {
		if err := printImageStreamTag(&ist, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printImageStreamImage(isi *imageapi.ImageStreamImage, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, isi.Name, opts.WithKind)
	created := fmt.Sprintf("%s ago", formatRelativeTime(isi.CreationTimestamp.Time))
	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", isi.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%s", name, created); err != nil {
		return err
	}
	if opts.Wide {
		if _, err := fmt.Fprintf(w, "\t%s\t%s", isi.Image.DockerImageReference, isi.Image.Name); err != nil {
			return err
		}

	}
	if err := appendItemLabels(isi.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printImageList(images *imageapi.ImageList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, image := range images.Items {
		if err := printImage(&image, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printImageStream(stream *imageapi.ImageStream, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, stream.Name, opts.WithKind)

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

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", stream.Namespace); err != nil {
			return err
		}
	}
	repo := stream.Spec.DockerImageRepository
	if len(repo) == 0 {
		repo = stream.Status.DockerImageRepository
	}
	if len(stream.Status.PublicDockerImageRepository) > 0 {
		repo = stream.Status.PublicDockerImageRepository
	}
	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s", name, repo, tags, latestTime); err != nil {
		return err
	}
	if err := appendItemLabels(stream.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
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

func printImageStreamList(streams *imageapi.ImageStreamList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, stream := range streams.Items {
		if err := printImageStream(&stream, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printProject(project *projectapi.Project, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, project.Name, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%s\t%s", name, project.Annotations[oapi.OpenShiftDisplayName], project.Status.Phase)
	if err := appendItemLabels(project.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return err
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

func printProjectList(projects *projectapi.ProjectList, w io.Writer, opts kprinters.PrintOptions) error {
	sort.Sort(SortableProjects(projects.Items))
	for _, project := range projects.Items {
		if err := printProject(&project, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printRoute(route *routeapi.Route, w io.Writer, opts kprinters.PrintOptions) error {
	tlsTerm := ""
	insecurePolicy := ""
	if route.Spec.TLS != nil {
		tlsTerm = string(route.Spec.TLS.Termination)
		insecurePolicy = string(route.Spec.TLS.InsecureEdgeTerminationPolicy)
	}

	name := formatResourceName(opts.Kind, route.Name, opts.WithKind)

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", route.Namespace); err != nil {
			return err
		}
	}
	var (
		matchedHost bool
		reason      string
		host        = route.Spec.Host

		admitted, errors = 0, 0
	)
	for _, ingress := range route.Status.Ingress {
		switch status, condition := ingressConditionStatus(&ingress, routeapi.RouteAdmitted); status {
		case kapi.ConditionTrue:
			admitted++
			if !matchedHost {
				matchedHost = ingress.Host == route.Spec.Host
				host = ingress.Host
			}
		case kapi.ConditionFalse:
			reason = condition.Reason
			errors++
		}
	}
	switch {
	case route.Status.Ingress == nil:
		// this is the legacy case, we should continue to show the host when talking to servers
		// that have not set status ingress, since we can't distinguish this condition from there
		// being no routers.
	case admitted == 0 && errors > 0:
		host = reason
	case errors > 0:
		host = fmt.Sprintf("%s ... %d rejected", host, errors)
	case admitted == 0:
		host = "Pending"
	case admitted > 1:
		host = fmt.Sprintf("%s ... %d more", host, admitted-1)
	}
	var policy string
	switch {
	case len(tlsTerm) != 0 && len(insecurePolicy) != 0:
		policy = fmt.Sprintf("%s/%s", tlsTerm, insecurePolicy)
	case len(tlsTerm) != 0:
		policy = tlsTerm
	case len(insecurePolicy) != 0:
		policy = fmt.Sprintf("default/%s", insecurePolicy)
	default:
		policy = ""
	}

	backends := append([]routeapi.RouteTargetReference{route.Spec.To}, route.Spec.AlternateBackends...)
	totalWeight := int32(0)
	for _, backend := range backends {
		if backend.Weight != nil {
			totalWeight += *backend.Weight
		}
	}
	var backendInfo []string
	for _, backend := range backends {
		switch {
		case backend.Weight == nil, len(backends) == 1 && totalWeight != 0:
			backendInfo = append(backendInfo, backend.Name)
		case totalWeight == 0:
			backendInfo = append(backendInfo, fmt.Sprintf("%s(0%%)", backend.Name))
		default:
			backendInfo = append(backendInfo, fmt.Sprintf("%s(%d%%)", backend.Name, *backend.Weight*100/totalWeight))
		}
	}

	var port string
	if route.Spec.Port != nil {
		port = route.Spec.Port.TargetPort.String()
	} else {
		port = "<all>"
	}

	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s", name, host, route.Spec.Path, strings.Join(backendInfo, ","), port, policy, route.Spec.WildcardPolicy); err != nil {
		return err
	}

	err := appendItemLabels(route.Labels, w, opts.ColumnLabels, opts.ShowLabels)

	return err
}

func ingressConditionStatus(ingress *routeapi.RouteIngress, t routeapi.RouteIngressConditionType) (kapi.ConditionStatus, routeapi.RouteIngressCondition) {
	for _, condition := range ingress.Conditions {
		if t != condition.Type {
			continue
		}
		return condition.Status, condition
	}
	return kapi.ConditionUnknown, routeapi.RouteIngressCondition{}
}

func printRouteList(routeList *routeapi.RouteList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, route := range routeList.Items {
		if err := printRoute(&route, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printDeploymentConfig(dc *appsapi.DeploymentConfig, w io.Writer, opts kprinters.PrintOptions) error {
	var desired string
	if dc.Spec.Test {
		desired = fmt.Sprintf("%d (during test)", dc.Spec.Replicas)
	} else {
		desired = fmt.Sprintf("%d", dc.Spec.Replicas)
	}

	containers := sets.NewString()
	if dc.Spec.Template != nil {
		for _, c := range dc.Spec.Template.Spec.Containers {
			containers.Insert(c.Name)
		}
	}
	//names := containers.List()
	referencedContainers := sets.NewString()

	triggers := sets.String{}
	for _, trigger := range dc.Spec.Triggers {
		switch t := trigger.Type; t {
		case appsapi.DeploymentTriggerOnConfigChange:
			triggers.Insert("config")
		case appsapi.DeploymentTriggerOnImageChange:
			if p := trigger.ImageChangeParams; p != nil && p.Automatic {
				var prefix string
				if len(containers) != 1 && !containers.HasAll(p.ContainerNames...) {
					sort.Sort(sort.StringSlice(p.ContainerNames))
					prefix = strings.Join(p.ContainerNames, ",") + ":"
				}
				referencedContainers.Insert(p.ContainerNames...)
				switch p.From.Kind {
				case "ImageStreamTag":
					triggers.Insert(fmt.Sprintf("image(%s%s)", prefix, p.From.Name))
				default:
					triggers.Insert(fmt.Sprintf("%s(%s%s)", p.From.Kind, prefix, p.From.Name))
				}
			}
		default:
			triggers.Insert(string(t))
		}
	}

	name := formatResourceName(opts.Kind, dc.Name, opts.WithKind)
	trigger := strings.Join(triggers.List(), ",")

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", dc.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%d\t%s\t%d\t%s", name, dc.Status.LatestVersion, desired, dc.Status.UpdatedReplicas, trigger); err != nil {
		return err
	}
	err := appendItemLabels(dc.Labels, w, opts.ColumnLabels, opts.ShowLabels)
	return err
}

func printDeploymentConfigList(list *appsapi.DeploymentConfigList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, dc := range list.Items {
		if err := printDeploymentConfig(&dc, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printClusterRole(role *authorizationapi.ClusterRole, w io.Writer, opts kprinters.PrintOptions) error {
	return printRole(authorizationapi.ToRole(role), w, opts)
}

func printClusterRoleList(list *authorizationapi.ClusterRoleList, w io.Writer, opts kprinters.PrintOptions) error {
	return printRoleList(authorizationapi.ToRoleList(list), w, opts)
}

func printClusterRoleBinding(roleBinding *authorizationapi.ClusterRoleBinding, w io.Writer, opts kprinters.PrintOptions) error {
	return printRoleBinding(authorizationapi.ToRoleBinding(roleBinding), w, opts)
}

func printClusterRoleBindingList(list *authorizationapi.ClusterRoleBindingList, w io.Writer, opts kprinters.PrintOptions) error {
	return printRoleBindingList(authorizationapi.ToRoleBindingList(list), w, opts)
}

func printIsPersonalSubjectAccessReview(a *authorizationapi.IsPersonalSubjectAccessReview, w io.Writer, opts kprinters.PrintOptions) error {
	_, err := fmt.Fprintf(w, "IsPersonalSubjectAccessReview\n")
	return err
}

func printRole(role *authorizationapi.Role, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, role.Name, opts.WithKind)
	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", role.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s", name); err != nil {
		return err
	}
	if err := appendItemLabels(role.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printRoleList(list *authorizationapi.RoleList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, role := range list.Items {
		if err := printRole(&role, w, opts); err != nil {
			return err
		}
	}

	return nil
}

func truncatedList(list []string, maxLength int) string {
	if len(list) > maxLength {
		return fmt.Sprintf("%s (%d more)", strings.Join(list[0:maxLength], ", "), len(list)-maxLength)
	}
	return strings.Join(list, ", ")
}

func printRoleBinding(roleBinding *authorizationapi.RoleBinding, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, roleBinding.Name, opts.WithKind)
	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", roleBinding.Namespace); err != nil {
			return err
		}
	}
	users, groups, sas, others := authorizationapi.SubjectsStrings(roleBinding.Namespace, roleBinding.Subjects)

	if _, err := fmt.Fprintf(w, "%s\t%s\t%v\t%v\t%v\t%v", name,
		roleBinding.RoleRef.Namespace+"/"+roleBinding.RoleRef.Name, truncatedList(users, 5),
		truncatedList(groups, 5), strings.Join(sas, ", "), strings.Join(others, ", ")); err != nil {
		return err
	}
	if err := appendItemLabels(roleBinding.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printRoleBindingList(list *authorizationapi.RoleBindingList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, roleBinding := range list.Items {
		if err := printRoleBinding(&roleBinding, w, opts); err != nil {
			return err
		}
	}

	return nil
}

func printOAuthClient(client *oauthapi.OAuthClient, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, client.Name, opts.WithKind)
	challenge := "FALSE"
	if client.RespondWithChallenges {
		challenge = "TRUE"
	}

	var maxAge string
	switch {
	case client.AccessTokenMaxAgeSeconds == nil:
		maxAge = "default"
	case *client.AccessTokenMaxAgeSeconds == 0:
		maxAge = "unexpiring"
	default:
		duration := time.Duration(*client.AccessTokenMaxAgeSeconds) * time.Second
		maxAge = duration.String()
	}

	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v", name, client.Secret, challenge, maxAge, strings.Join(client.RedirectURIs, ",")); err != nil {
		return err
	}
	if err := appendItemLabels(client.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printOAuthClientList(list *oauthapi.OAuthClientList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printOAuthClient(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printOAuthClientAuthorization(auth *oauthapi.OAuthClientAuthorization, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, auth.Name, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", name, auth.UserName, auth.ClientName, strings.Join(auth.Scopes, ","))
	return err
}

func printOAuthClientAuthorizationList(list *oauthapi.OAuthClientAuthorizationList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printOAuthClientAuthorization(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printOAuthAccessToken(token *oauthapi.OAuthAccessToken, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, token.Name, opts.WithKind)
	created := token.CreationTimestamp
	expires := "never"
	if token.ExpiresIn > 0 {
		expires = created.Add(time.Duration(token.ExpiresIn) * time.Second).String()
	}
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, token.UserName, token.ClientName, created, expires, token.RedirectURI, strings.Join(token.Scopes, ","))
	return err
}

func printOAuthAccessTokenList(list *oauthapi.OAuthAccessTokenList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printOAuthAccessToken(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printOAuthAuthorizeToken(token *oauthapi.OAuthAuthorizeToken, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, token.Name, opts.WithKind)
	created := token.CreationTimestamp
	expires := created.Add(time.Duration(token.ExpiresIn) * time.Second)
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, token.UserName, token.ClientName, created, expires, token.RedirectURI, strings.Join(token.Scopes, ","))
	return err
}

func printOAuthAuthorizeTokenList(list *oauthapi.OAuthAuthorizeTokenList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printOAuthAuthorizeToken(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printUser(user *userapi.User, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, user.Name, opts.WithKind)
	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s", name, user.UID, user.FullName, strings.Join(user.Identities, ", ")); err != nil {
		return err
	}
	if err := appendItemLabels(user.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printUserList(list *userapi.UserList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printUser(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printIdentity(identity *userapi.Identity, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, identity.Name, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", name, identity.ProviderName, identity.ProviderUserName, identity.User.Name, identity.User.UID)
	return err
}

func printIdentityList(list *userapi.IdentityList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printIdentity(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printUserIdentityMapping(mapping *userapi.UserIdentityMapping, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, mapping.Name, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", name, mapping.Identity.Name, mapping.User.Name, mapping.User.UID)
	return err
}

func printGroup(group *userapi.Group, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, group.Name, opts.WithKind)
	_, err := fmt.Fprintf(w, "%s\t%s\n", name, strings.Join(group.Users, ", "))
	return err
}

func printGroupList(list *userapi.GroupList, w io.Writer, opts kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printGroup(&item, w, opts); err != nil {
			return err
		}
	}
	return nil
}

func appendLabels(itemLabels map[string]string, columnLabels []string) string {
	var buffer bytes.Buffer

	for _, cl := range columnLabels {
		buffer.WriteString(fmt.Sprint("\t"))
		if il, ok := itemLabels[cl]; ok {
			buffer.WriteString(fmt.Sprint(il))
		} else {
			buffer.WriteString("<none>")
		}
	}

	return buffer.String()
}

func appendAllLabels(showLabels bool, itemLabels map[string]string) string {
	var buffer bytes.Buffer

	if showLabels {
		buffer.WriteString(fmt.Sprint("\t"))
		buffer.WriteString(labels.FormatLabels(itemLabels))
	}
	buffer.WriteString("\n")

	return buffer.String()
}

func appendItemLabels(itemLabels map[string]string, w io.Writer, columnLabels []string, showLabels bool) error {
	if _, err := fmt.Fprint(w, appendLabels(itemLabels, columnLabels)); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, appendAllLabels(showLabels, itemLabels)); err != nil {
		return err
	}
	return nil
}

func printClusterResourceQuota(resourceQuota *quotaapi.ClusterResourceQuota, w io.Writer, options kprinters.PrintOptions) error {
	name := formatResourceName(options.Kind, resourceQuota.Name, options.WithKind)

	if _, err := fmt.Fprintf(w, "%s", name); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\t%s", metav1.FormatLabelSelector(resourceQuota.Spec.Selector.LabelSelector)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\t%s", resourceQuota.Spec.Selector.AnnotationSelector); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, appendLabels(resourceQuota.Labels, options.ColumnLabels)); err != nil {
		return err
	}
	_, err := fmt.Fprint(w, appendAllLabels(options.ShowLabels, resourceQuota.Labels))
	return err
}

func printClusterResourceQuotaList(list *quotaapi.ClusterResourceQuotaList, w io.Writer, options kprinters.PrintOptions) error {
	for i := range list.Items {
		if err := printClusterResourceQuota(&list.Items[i], w, options); err != nil {
			return err
		}
	}
	return nil
}

func printAppliedClusterResourceQuota(resourceQuota *quotaapi.AppliedClusterResourceQuota, w io.Writer, options kprinters.PrintOptions) error {
	return printClusterResourceQuota(quotaapi.ConvertAppliedClusterResourceQuotaToClusterResourceQuota(resourceQuota), w, options)
}

func printAppliedClusterResourceQuotaList(list *quotaapi.AppliedClusterResourceQuotaList, w io.Writer, options kprinters.PrintOptions) error {
	for i := range list.Items {
		if err := printClusterResourceQuota(quotaapi.ConvertAppliedClusterResourceQuotaToClusterResourceQuota(&list.Items[i]), w, options); err != nil {
			return err
		}
	}
	return nil
}

func printRoleBindingRestriction(rbr *authorizationapi.RoleBindingRestriction, w io.Writer, options kprinters.PrintOptions) error {
	name := formatResourceName(options.Kind, rbr.Name, options.WithKind)
	subjectType := roleBindingRestrictionType(rbr)
	subjectList := []string{}
	const numOfSubjectsShown = 3
	switch {
	case rbr.Spec.UserRestriction != nil:
		for _, user := range rbr.Spec.UserRestriction.Users {
			subjectList = append(subjectList, user)
		}
		for _, group := range rbr.Spec.UserRestriction.Groups {
			subjectList = append(subjectList, fmt.Sprintf("group(%s)", group))
		}
		for _, selector := range rbr.Spec.UserRestriction.Selectors {
			subjectList = append(subjectList,
				metav1.FormatLabelSelector(&selector))
		}
	case rbr.Spec.GroupRestriction != nil:
		for _, group := range rbr.Spec.GroupRestriction.Groups {
			subjectList = append(subjectList, group)
		}
		for _, selector := range rbr.Spec.GroupRestriction.Selectors {
			subjectList = append(subjectList,
				metav1.FormatLabelSelector(&selector))
		}
	case rbr.Spec.ServiceAccountRestriction != nil:
		for _, sa := range rbr.Spec.ServiceAccountRestriction.ServiceAccounts {
			subjectList = append(subjectList, fmt.Sprintf("%s/%s",
				sa.Namespace, sa.Name))
		}
		for _, ns := range rbr.Spec.ServiceAccountRestriction.Namespaces {
			subjectList = append(subjectList, fmt.Sprintf("%s/*", ns))
		}
	}

	if options.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", rbr.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s", name); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\t%s", subjectType); err != nil {
		return err
	}
	subjects := "<none>"
	if len(subjectList) > numOfSubjectsShown {
		subjects = fmt.Sprintf("%s + %d more...",
			strings.Join(subjectList[:numOfSubjectsShown], ", "),
			len(subjectList)-numOfSubjectsShown)
	} else if len(subjectList) > 0 {
		subjects = strings.Join(subjectList, ", ")
	}
	_, err := fmt.Fprintf(w, "\t%s\n", subjects)
	return err
}

func printRoleBindingRestrictionList(list *authorizationapi.RoleBindingRestrictionList, w io.Writer, options kprinters.PrintOptions) error {
	for i := range list.Items {
		if err := printRoleBindingRestriction(&list.Items[i], w, options); err != nil {
			return err
		}
	}
	return nil
}

func printTemplateInstance(templateInstance *templateapi.TemplateInstance, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, templateInstance.Name, opts.WithKind)

	if opts.WithNamespace {
		if _, err := fmt.Fprintf(w, "%s\t", templateInstance.Namespace); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s\t%s", name, templateInstance.Spec.Template.Name); err != nil {
		return err
	}
	if err := appendItemLabels(templateInstance.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printTemplateInstanceList(list *templateapi.TemplateInstanceList, w io.Writer, opts kprinters.PrintOptions) error {
	for i := range list.Items {
		if err := printTemplateInstance(&list.Items[i], w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printBrokerTemplateInstance(brokerTemplateInstance *templateapi.BrokerTemplateInstance, w io.Writer, opts kprinters.PrintOptions) error {
	name := formatResourceName(opts.Kind, brokerTemplateInstance.Name, opts.WithKind)

	if _, err := fmt.Fprintf(w, "%s\t%s/%s", name, brokerTemplateInstance.Spec.TemplateInstance.Namespace, brokerTemplateInstance.Spec.TemplateInstance.Name); err != nil {
		return err
	}
	if err := appendItemLabels(brokerTemplateInstance.Labels, w, opts.ColumnLabels, opts.ShowLabels); err != nil {
		return err
	}
	return nil
}

func printBrokerTemplateInstanceList(list *templateapi.BrokerTemplateInstanceList, w io.Writer, opts kprinters.PrintOptions) error {
	for i := range list.Items {
		if err := printBrokerTemplateInstance(&list.Items[i], w, opts); err != nil {
			return err
		}
	}
	return nil
}

func printSecurityContextConstraints(item *securityapi.SecurityContextConstraints, w io.Writer, options kprinters.PrintOptions) error {
	priority := "<none>"
	if item.Priority != nil {
		priority = fmt.Sprintf("%d", *item.Priority)
	}

	_, err := fmt.Fprintf(w, "%s\t%t\t%v\t%s\t%s\t%s\t%s\t%s\t%t\t%v\n", item.Name, item.AllowPrivilegedContainer,
		item.AllowedCapabilities, item.SELinuxContext.Type,
		item.RunAsUser.Type, item.FSGroup.Type, item.SupplementalGroups.Type, priority, item.ReadOnlyRootFilesystem, item.Volumes)
	return err
}

func printSecurityContextConstraintsList(list *securityapi.SecurityContextConstraintsList, w io.Writer, options kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printSecurityContextConstraints(&item, w, options); err != nil {
			return err
		}
	}

	return nil
}

func printRangeAllocation(item *securityapi.RangeAllocation, w io.Writer, options kprinters.PrintOptions) error {
	_, err := fmt.Fprintf(w, "%s\t%s\t0x%x\n", item.Name, item.Range, item.Data)
	return err
}

func printRangeAllocationList(list *securityapi.RangeAllocationList, w io.Writer, options kprinters.PrintOptions) error {
	for _, item := range list.Items {
		if err := printRangeAllocation(&item, w, options); err != nil {
			return err
		}
	}

	return nil
}
