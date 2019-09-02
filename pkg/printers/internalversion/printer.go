package internalversion

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kprinters "k8s.io/kubernetes/pkg/printers"
	kprintersinternal "k8s.io/kubernetes/pkg/printers/internalversion"

	authorizationapi "github.com/openshift/openshift-apiserver/pkg/authorization/apis/authorization"
	oauthapi "github.com/openshift/openshift-apiserver/pkg/oauth/apis/oauth"
	userapi "github.com/openshift/openshift-apiserver/pkg/user/apis/user"

	appsinternalprinters "github.com/openshift/openshift-apiserver/pkg/apps/printers/internalversion"
	authinternalprinters "github.com/openshift/openshift-apiserver/pkg/authorization/printers/internalversion"
	buildinternalprinters "github.com/openshift/openshift-apiserver/pkg/build/printers/internalversion"
	imageinternalprinters "github.com/openshift/openshift-apiserver/pkg/image/printers/internalversion"
	projectinternalprinters "github.com/openshift/openshift-apiserver/pkg/project/printers/internalversion"
	quotainternalprinters "github.com/openshift/openshift-apiserver/pkg/quota/printers/internalversion"
	routeinternalprinters "github.com/openshift/openshift-apiserver/pkg/route/printers/internalversion"
	securityinternalprinters "github.com/openshift/openshift-apiserver/pkg/security/printers/internalversion"
	templateinternalprinters "github.com/openshift/openshift-apiserver/pkg/template/printers/internalversion"
)

var (
	roleBindingColumns = []string{"Name", "Role", "Users", "Groups", "Service Accounts", "Subjects"}
	roleColumns        = []string{"Name"}

	oauthClientColumns              = []string{"Name", "Secret", "WWW-Challenge", "Token-Max-Age", "Redirect URIs"}
	oauthClientAuthorizationColumns = []string{"Name", "User Name", "Client Name", "Scopes"}
	oauthAccessTokenColumns         = []string{"Name", "User Name", "Client Name", "Created", "Expires", "Redirect URI", "Scopes"}
	oauthAuthorizeTokenColumns      = []string{"Name", "User Name", "Client Name", "Created", "Expires", "Redirect URI", "Scopes"}

	userColumns                = []string{"Name", "UID", "Full Name", "Identities"}
	identityColumns            = []string{"Name", "IDP Name", "IDP User Name", "User Name", "User UID"}
	userIdentityMappingColumns = []string{"Name", "Identity", "User Name", "User UID"}
	groupColumns               = []string{"Name", "Users"}
)

func init() {
	// TODO this should be eliminated
	kprintersinternal.AddHandlers = func(p kprinters.PrintHandler) {
		// kubernetes handlers
		kprintersinternal.AddKubeHandlers(p)

		appsinternalprinters.AddHandlers(p)
		buildinternalprinters.AddHandlers(p)
		imageinternalprinters.AddHandlers(p)
		projectinternalprinters.AddHandlers(p)
		routeinternalprinters.AddHandlers(p)
		templateinternalprinters.AddHandlers(p)

		// security.openshift.io handlers
		securityinternalprinters.AddSecurityOpenShiftHandler(p)

		// authorization.openshift.io handlers
		authinternalprinters.AddAuthorizationOpenShiftHandler(p)

		// quota.openshift.io handlers
		quotainternalprinters.AddQuotaOpenShiftHandler(p)

		// Legacy handlers
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
}

// formatResourceName receives a resource kind, name, and boolean specifying
// whether or not to update the current name to "kind/name"
func formatResourceName(kind schema.GroupKind, name string, withKind bool) string {
	if !withKind || kind.Empty() {
		return name
	}

	return strings.ToLower(kind.String()) + "/" + name
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
