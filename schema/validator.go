package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	tmpl "text/template"
)

/*
Encapsulate variety of rules around Podman Quadlet options and their corresponding Podman CLI representations
e.g.
Quadlet:    AddCapability=CAP
Podman CLI: --cap-add CAP
Notes: List of possible values is based on SELinux capabilities. Attribute AddCapability may be listed many times.

Attribute:
  Quadlet: "AddCapability"
  Podman: "--cap-add"
  Values[0]={"CAP_IPC_OWNER", "Give container ownership permission for IPC", "Bypass permission checks for System V IPC (Inter-Process Communication) objects, such as shared memory segments, message queues, and semaphore sets."}
  QuadletTemplate: "{.Quadlet}={.Value}"
  PodmanTemplate: "{.Podman} {.value}"

Quadlet: Annotation=”XYZ”
Podman CLI: --annotation “XYZ”
Notes: Value is expected to be quoted

Quadlet: AppArmor=”alternate-profile”
Podman CLI: --security-opt apparmor=alternate-profile
Notes: Value is quoted for Quadlet but not for CLI. However, CLI uses a different attribute with a compound value.

Quadlet: AutoUpdate=registry
Podman CLI: --label “io.containers.autoupdate=registry”
Notes: Value not quoted for quadlet, but different attribute with quoted compound value for CLI.

Quadlet: CgroupsMode=no-conmon
Podman CLI: --cgroups=no-conmon
Notes: CLI uses equal sign instead of space to separate value

Quadlet: EnvironmentHost=true
Podman CLI: --env-host
Notes: Boolean attribute value can be represented by flag only in CLI if value is true. Likewise, omitting the flag is same as 'false'

Quadlet: Environment=foo=bar
Podman CLI: --env foo=bar
Notes: Equal sign in quadlet value. The first equal sign separates the value from attribute name. Any after that are part of the value.

Quadlet: Exec=/usr/bin/command
Podman CLI: Command after image specification - /usr/bin/command
Notes: Not solved with a template. Needs custom logic to handle. Maybe a special handler property with a few defined keys to trigger specific handling?

Quadlet: ReloadCmd=/usr/bin/command
Podman CLI: Add ExecReload and run exec with the value
Notes: This is not actually for Podman CLI, but rather a description of what Quadlet engine will do based on the value. Need to ignore / validate only. Special handler?

Assumption: Quadlet is always key=value, so common parsing logic to extract attribute name and value. Probably must also support multpiple space-separated values.
Assumption: IF we support parsing Podman command lines to generate quadlet, will require complex parsing logic. Podlet already does this. Probably no value adding here.
*/

// Common interface for logic to validate and format attributes
type Handler interface {
	Validate(attr *Attribute) bool
	Format(attr *Attribute) error
}

type CommonHandler struct{}

func (h *CommonHandler) Validate(attr *Attribute) bool {
	isValid := false
	// Enumerated values
	// Freeform text value (add a regex to handle specific types of values like IP, Port, integer, decimal, email, etc.?)
	for _, v := range attr.Schema.Values {
		//If freeform, value will be empty string. If applicable, there will be a regex validator
		if v.Value == "" {
			if v.Validator != "" {
				//validate via regex
				match, _ := regexp.MatchString(v.Validator, attr.Value)
				if match {
					// valid
					isValid = true
					break
				} else {
					// Not valid
					break
				}
			}
			// otherwise acccept any value as valid
			isValid = true
			break
		}
		// If match an enumerated value, is valid
		if v.Value == attr.Value {
			isValid = true
			break
		}
	}
	return isValid
}

/*
	t1 := template.New("t1")
    t1, err := t1.Parse("{{.attr.Schema.PodmanKey}} {{.attr.Value}}")
    if err != nil {
        panic(err)
    }
*/

func (h *CommonHandler) Format(template tmpl.Template, attr *Attribute) error {
	if !h.Validate(attr) {
		return fmt.Errorf("Validation Failed")
	}

	buf := &bytes.Buffer{}
	err := template.Execute(buf, attr)
	if err != nil {
		return err
	}
	attr.FormattedValue = buf.String()

	return nil
}

/*
Need a way to tell processing logic to handle things beyond attribute validation and formatting:
 - Instruction to Quadlet engine (ie. validate only)
 - Command for Podman to execute (ie. special placement at end of podman command line)
 - other specific handling...
 Maybe just use conditional logic on the section type and attribute type. Everything that needs special handling is ultimately a specific type of attribute.
*/

type QuadletType string

const (
	Pod_Quadlet       QuadletType = "Pod"
	Container_Quadlet QuadletType = "Container"
	Volume_Quadlet    QuadletType = "Volume"
	Network_Quadlet   QuadletType = "Network"
	Kube_Quadlet      QuadletType = "Kube"
)

type SectionType string

const (
	Unit_Section      SectionType = "Unit"
	Pod_Section       SectionType = "Pod"
	Container_Section SectionType = "Container"
	Volume_Section    SectionType = "Volume"
	Network_Section   SectionType = "Network"
	Service_Section   SectionType = "Service"
	Install_Section   SectionType = "Install"
)

type AttributeType string

const (
	Environment AttributeType = "Environment"
	Volume      AttributeType = "Volume"
)

var schemaMap map[string]QuadletSchema

type QuadletSchema struct {
	Type     QuadletType     `json:"type"`
	Sections []SectionSchema `json:"sections"`
}

type SectionSchema struct {
	Type       SectionType       `json:"type"`
	Attributes []AttributeSchema `json:"attributes"`
}

type AttributeSchema struct {
	Type                  AttributeType `json:"type"`
	QuadletKey            string        `json:"quadlet-key"`    //Formated quadlet attribute key
	PodmanKey             string        `json:"podman-key"`     //Formatted Podman CLI attribute key
	Values                []ValueSchema `json:"values"`         //[value][description][cautions][regexp validator]. Free-form string value denoted as empty string.
	AllowMultiple         bool          `json:"allow-multiple"` //True if this attribute may be specified multiple times with different values
	QuadletTemplateString string        `json:"quadlet-template"`
	PodmanTemplateString  string        `json:"podman-template"`
	QuadletTemplate       tmpl.Template `json:"ignore-empty"`
	PodmanTemplate        tmpl.Template `json:"ignore-empty"`
	Handler               Handler       `json:"ignore-empty"` //Interface reference to function used to validate and format the value
}

type ValueSchema struct {
	Value       string `json:"value"`
	Description string `json:"description"`
	Cautions    string `json:"cautions"`
	Validator   string `json:"validator"`
}

type Attribute struct {
	Value          string //change this to a slice to handle multiple values (e.g. environment variables and other repeatable attributes)?
	Schema         *AttributeSchema
	FormattedValue string
	Warning        string
	Error          string
}

func main() {

	attributeSchemas := []AttributeSchema{}
	attributeSchema := AttributeSchema{
		Type:                  "Name",
		QuadletKey:            "QuadletName",
		PodmanKey:             "PodmanName",
		Values:                []ValueSchema{{"value", "description", "caution1", "validator"}, {"value2", "description2", "caution2", "validator2"}},
		AllowMultiple:         false,
		QuadletTemplateString: "some golang quadlet {{.}} template",
		PodmanTemplateString:  "some golang podman {{.}} template",
	}
	attributeSchemas = append(attributeSchemas, attributeSchema)

	sections := []SectionSchema{}
	sectionSchema := SectionSchema{
		Type:       Container_Section,
		Attributes: attributeSchemas,
	}
	sections = append(sections, sectionSchema)

	quadletSchema := QuadletSchema{
		Type:     Container_Quadlet,
		Sections: sections,
	}

	schemaMap = make(map[string]QuadletSchema)
	schemaMap["Pod"] = quadletSchema
	schemaMap["Container"] = quadletSchema

	var schemaBytes []byte
	var err error
	if schemaBytes, err = json.MarshalIndent(&schemaMap, "", "  "); err != nil {
		panic(err)
	}
	fmt.Println(string(schemaBytes))
}

/*
Init logic:

- Parse JSON file containing quadlet, section and attribute definitions and valid values, descriptions, cautions
- Construct and assemble QuadletSchema, SectionSchema, AttributeSchema and add to map to support processing logic. (e.g. map[".container"] = QuadletSchema(Container))


Processing logic:

- Parse INI file
- Determine quadlet type and section
- For each line in section, pass quadlet type, section and line to a processing feeder function that extracts attribute name and value, looks
  up the AttributeSchema struct that applies and creates an Attribute struct that holds the AttributeSchema and the supplied value.
- Build up the complete set of Attributes for the quadlet, sort them by type so that command lines are consistently ordered (e.g. env, vol, network, label, image, command)
- Output the podman cli command based on the sorted attributes OR output errors or warnings collected during processing if only validating the Quadlet file.
  This implies the Attribute struct should have fields for value, warning, error
*/
