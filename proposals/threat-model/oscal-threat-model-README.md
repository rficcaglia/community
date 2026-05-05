# Proposal: OSCAL Model for Threat Analysis

## 1. Overview

OSCAL does not provide a top level model for threat analysis.  We find this problematic as the implementation of controls
must be grounded in thoughtful consideration of risks to the system. OSCAL does treat risks as a part of Assessment and POA&M schemas and
Assessment of a control implementation must consider the degree to which a risk is mitigated.  

But how do you define where to look for risks during assessment? How do you define the magnitude and impact of a risk so that the assessment can measure unmitigated risk?

On a further contextual note, we focus on risks by malicious insider or external actor activity.  Of course there are intrinsic engineering, operational and environmental risks:
- fires, floods, pandemics, etc.
- mechanical or infrastructure failures
- human operator error
- design flaws
- bugs that impact functionality (or inadvertently C/I/A to legitimate and well-behaved system users)
- financial losses

These are modeled best in other domains (e.g. climate science, financial risk analysis, SDLC, HR, SCRM, etc.).  Here we consider risks
that originate by a motivated internal or external attacker who rationally and systematically attempts to subvert the Confidentiality,
Integrity, or Availability (C/I/A) of the system, its data, or functionality for fun or profit or idealism. These intentional threats to the
system represent the definition of controllable and preventable and addressable risks to the cloud native, or AI native, system.

As we define our cloud native or AI agentic systems as code, we use OSCAL to define compliance as code. We must therefore
build the control implementation on a foundation model that supports defining risks to the system as code. Here we define 
a threat model schema and provide examples of OSCAL implementation germane to a cloud native and AI agentic system.

## 2. Goals

### 2.1 Problem Statement

2.1.1 Given a *cloud native* and/or *AI native (agentic)* system or system component, define in code:
- What are the expected states of the system?
- What conditions and variables can be measured that differentiate different states?
- What actions cause an expected state transition in the system? How do the conditions and variables change in response to each action?
- What inputs and observable outputs are associated with each state transition?
- The specific states (and the associated permitted actions and observable outputs) that should be "invariant" across the system and all components such that, if violated, represent a vulnerability?
- Which Threat Actors are in scope for the system?
- Which Attack techniques and tactics are in scope for the system?
- Which defense and mitigation techniques and tactics are available as capabilities within or alongside the system?
- How do we enumerate the vulnerabilities which, if successfully exploited by a Threat Actor using Attack action(s) (e.g. bypassing or disabling all relevant mitigations), result in an measurable assessment risk?
- How can we build a knowledge base of real world examples (aka Incidents) that can inform our efforts?

2.1.2 Measure the system's robustness to:
- Measure Attacker Success Rate (ASR) for all enumerable threats
- Measure Defender Success Rate (DSR) in terms of Protective, Detective and Responsive (P/D/R) capabilities and actions

2.1.3 Deliver Code
- All output artifacts must support machine execution
- Support AI tooling:
  - for artifact generation
  - for artifact usage

### 2.2 (Re)Use Established Standards

Connecting OSCAL to other existing threat vocabularies allows for easier integration and broader reuse.

2.2.1 MITRE ATT&CK and [ATLAS](https://atlas.mitre.org/)

MITRE ATT&CK® is a knowledge base of tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for grounding this OSCAL schema to a proven framework that is widely supported by all cloud providers, security tools, and open source.

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is an AI-specific knowledge base of adversary tactics and techniques from Al red teams and security groups.

Both ATT&CK and ATLAS have python library support for accessing and manipulating the data, which makes alignment (for import/export) desirable.

2.2.2 STIX 2.1

Since [MITRE ATT&CK was already supported in STIX 2.1 collections](https://github.com/mitre-attack/attack-stix-data), and also [ATLAS](https://github.com/mitre-atlas/atlas-navigator-data?tab=readme-ov-file#distributed-files), it was natural to align this model to many of the same concepts and definitions.
Refer to the [README](./STIX-Modifications-README.md) for details on which SDOs are used.

### 2.3 Other Solutions Considered

Before describing the proposed OSCAL schema - we discuss other existing threat modeling frameworks that inspired our work. We considered many threat model
frameworks and will highlight 2 popular frameworks that informed the analysis: STRIDE and [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/). 
That said, the observations generally apply to many other threat model frameworks.

2.3.1 STRIDE

Presented by Microsoft in 2006 its intent was for secure software and not a cloud (or SaaS, ASP, Service-Oriented) native system. However most of its core ideas are still
very useful and valid:

- Assume the attackers have the sources and the specs (ie. obscurity != security)
- Remove SPOFs and fail secure (this could be modernized to include secure by default/design)
- Always use least privilege
- Always follow K.I.S.S
- Separation of privileges (in cloud native terms - always separate data access from control plane and explicitly define shared responsibility model)
- Test everything (otherwise stated: that which has not been tested can be assumed to fail insecurely)
- Avoid shared resources, access

STRIDE also articulated many security properties we would maintain today for cloud native:

- Confidentiality
- Integrity
- Availability
- Authentication (aka Identity)
- Authorization (aka permissions)
- Non-repudiation (audit, forensics)

The core idea was STRIDE maps the following threats to these security properties:

* Spoofing -> Authentication
* Tampering -> Integrity
* Repudiation -> Non-repudiation
* Information disclosure -> Confidentiality
* Denial of Service -> Availability
* Elevation of privilege -> Authorization

However at this point Data Flow Diagrams are used to:

```
"Decompose your system into relevant components, analyze each component for susceptibility to the threats,
and mitigate the threats...repeat the process until you are comfortable with any remaining threats."
```

Even if we produce DFDs for cloud and AI, eg:

- Data flow => API call for network and/or control plane
- Data store => API call for data
- Process => compute resource (or API call e.g. Lambda Function invocation)
- Interactors => compute resource or AI Agent
- Trust boundary => Cloud or Agent Identity (e.g. IAM) policy

The STRIDE manifesto leaves this ambiguous as to how to accomplish this, especially with respect to trust boundaries which are the core idea in STRIDE outputs:

```
"Getting the DFD right is key to getting the threat model right. Spend enough time on yours...
Trust boundaries are perhaps the most subjective of all...Trust is complex.
As you consider threats to [a] data flow, it may occur to you..." 
```

Ignoring for now the ability of newer multi-modal LLMs to process diagrams, diagrams are not a code artifact.  
Nor is the subjective, ad hoc, and intuition-based nature of manually mapping properties to DFD elements,
and arbitrarily defining trust, measurably precise or repetable. 
There is no measurable, objective definition of "analyze", "consider", "susceptibility", "mitigation", "comfortable", 
"remaining threats", "right", "enough", or "complex".

To be part of the "as-code", model-based ecosystem enabled by OSCAL, we need threat-model-as-code. STRIDE doesn't achieve this.

Finally a core tenet of STRIDE's approach, ignoring the diagram mechanics and notation, is that 
"software comes under a predictable set of threats" which is demonstrably false for complex cloud systems, 
and provably false for AI based systems. Any OSCAL approach must cover all the [*provably unpredictable*](https://en.wikipedia.org/wiki/2-EXPTIME) 
threats that emerge from the combinatorial explosion of all possible cloud and AI control plane and data APIs 
that can change state and elicit unexpected behavior or data.

2.3.2 [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)

The Threat Modeling Manifesto is aligned with an Agile Manfiesto philosophy.

```
"The Manifesto contains ideas, but is not a how-to, and is methodology-agnostic."
```

It focuses on core Values:

- A culture of finding and fixing design issues over checkbox compliance.
- People and collaboration over processes, methodologies, and tools.
- A journey of understanding over a security or privacy snapshot.
- Doing threat modeling over talking about it.
- Continuous refinement over a single delivery.

and Principles:

- The best use of threat modeling is to improve the security and privacy of a system through early and frequent analysis.
- Threat modeling must align with an organization’s development practices and follow design changes in iterations that are each scoped to manageable portions of the system.
- The outcomes of threat modeling are meaningful when they are of value to stakeholders.
- Dialog is key to establishing the common understandings that lead to value, while documents record those understandings, and enable measurement. 

It also explores Patterns and Anti-Patterns in threat modeling for humans.

While many of the values and principles do apply, the current focus is an "as-code" approach that increasingly targets, and uses, AI and does not rely solely on human expertise.
Specifically, using OSCAL to automate and continuously threat model would align with identifying design flaws before implementation and delivery.
OSCAL automated threat-model-as-code would allow for (version controlled, reviewable) collaborative code processes, methodologies, and tools.
OSCAL is meant to be executed for assessment continuously at each step of the SDLC from code through DevSecOps vs. a single, point-in-time snapshot.
Using a standard schema and methodology allows for measurement and automated reporting that leads to a shared understanding of the security and compliance which
translates to high value delivery.

2.3.3 Honorable Mention: [pytm](https://github.com/izar/pytm)

pytm is a python package that allows for "as-code" threat modeling and aligns with several of the vocabularies we align to.  We could see it being extremely easy
to manually or via LLM construct pytm code from the OSCAL threat model output. A future effort might collaborate with pytm and add support for OSCAL.

## 3. Model Schema

The schema below reflects the actor-centric deduplication design described in §4. Key additions over a naive
cartesian-product model:

- `threat-actor.capabilities` (§4.3.2) — per-actor capability descriptors that drive the generator's eligibility
  and non-baseline weight checks.
- `risk-scenario.actor-capability-modifiers` (§4.3.1) — per-actor P/D/R weight overrides emitted only when an
  actor's capability produces a value that differs from the 1.0 baseline.

These two fields are the only schema requirements for the deduplication algorithm in §4.4. The concrete P/D/R
delta values and technique-exclusion gates referenced by the generator are documented in the AC-2 reference table
(§4.5).

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "http://sunstonesecure.com/ns/oscal/1.0/1.2.0/proposal/oscal-threat-model-schema.json",
  "$comment": "OSCAL Threat Model: JSON Schema",
  "type": "object",
  "definitions": {
    "threat-model": {
      "title": "Threat Model",
      "description": "A structured model for defining system states, threat actors, attack techniques, and risk scenarios for cloud-native and AI-agentic systems.",
      "type": "object",
      "properties": {
        "uuid": {
          "title": "Threat Model Universally Unique Identifier",
          "description": "A globally unique identifier for this threat model instance.",
          "$ref": "#/definitions/UUIDDatatype"
        },
        "metadata": {
          "$ref": "#/definitions/metadata"
        },
        "import-system-definition": {
          "title": "Import System Definition",
          "description": "Links this threat model to the specific system definition (e.g., SSP or Component Definition) being analyzed.",
          "type": "array",
          "minItems": 1,
          "items": {
            "$ref": "#/definitions/import-definition"
          }
        },
        "system-state-model": {
          "title": "System State Model",
          "description": "Defines the expected states, actions, variables, transitions, and invariants of the system (Goal 2.1.1).",
          "$ref": "#/definitions/system-state-model"
        },
        "threat-landscape": {
          "title": "Threat Landscape",
          "description": "Defines the scope of threat actors and attack techniques (Goal 2.1.1, 2.2).",
          "$ref": "#/definitions/threat-landscape"
        },
        "defense-landscape": {
          "title": "Defense Landscape",
          "description": "Defines available defense and mitigation capabilities.",
          "$ref": "#/definitions/defense-landscape"
        },
        "risk-analysis": {
          "title": "Risk Analysis and Scenarios",
          "description": "Enumerates vulnerabilities, scenarios, and measures robustness (ASR/DSR) (Goal 2.1.2).",
          "$ref": "#/definitions/risk-analysis"
        },
        "back-matter": {
          "$ref": "#/definitions/back-matter"
        }
      },
      "required": [
        "uuid",
        "metadata",
        "system-state-model"
      ],
      "additionalProperties": false
    },
    "system-state-model": {
      "type": "object",
      "properties": {
        "variables": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/state-variable"
          },
          "description": "Conditions and variables that can be measured to differentiate states."
        },
        "states": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/system-state"
          },
          "description": "The expected states of the system."
        },
        "actions": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/system-action"
          },
          "description": "The discrete system functions or API calls that cause state transitions."
        },
        "observables": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/observable-definition"
          },
          "description": "Definitions of expected outputs (SCOs) generated by transitions."
        },
        "transitions": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/state-transition"
          },
          "description": "The logic connecting Actions to State changes."
        },
        "invariants": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/invariant"
          },
          "description": "Specific states or outputs that must be invariant across the system; violations represent vulnerabilities."
        }
      }
    },
    "state-variable": {
      "type": "object",
      "properties": {
        "id": { "$ref": "#/definitions/TokenDatatype" },
        "name": { "$ref": "#/definitions/StringDatatype" },
        "type": {
          "type": "string",
          "enum": ["boolean", "integer", "string", "enum", "float", "dictionary"]
        },
        "description": { "$ref": "#/definitions/MarkupMultilineDatatype" }
      },
      "required": ["id", "name", "type"]
    },
    "system-state": {
      "type": "object",
      "properties": {
        "id": { "$ref": "#/definitions/TokenDatatype" },
        "title": { "$ref": "#/definitions/MarkupLineDatatype" },
        "description": { "$ref": "#/definitions/MarkupMultilineDatatype" },
        "is_safe": { 
          "type": "boolean",
          "description": "If true, asserts this state is within safe operational boundaries." 
        },
        "is_terminal": { 
          "type": "boolean",
          "description": "If true, indicates this is a final state (e.g. Terminated, Crashed)." 
        },
        "conditions": {
          "type": "array",
          "items": { "$ref": "#/definitions/condition" },
          "description": "Variable values that define this state (e.g., 'instance_status' == 'running')."
        }
      },
      "required": ["id", "title"]
    },
    "system-action": {
      "type": "object",
      "description": "A discrete system function, procedure, or API call.",
      "properties": {
        "id": { "$ref": "#/definitions/TokenDatatype" },
        "name": { "$ref": "#/definitions/StringDatatype" },
        "description": { "$ref": "#/definitions/MarkupMultilineDatatype" },
        "action_type": {
          "type": "string",
          "enum": ["api-call", "command-execution", "process-spawn", "network-connection", "file-io", "authorization-grant"]
        },
        "api_method": { "$ref": "#/definitions/StringDatatype" },
        "api_endpoint": { "$ref": "#/definitions/StringDatatype" },
        "parameters": {
          "type": "object",
          "description": "Schema or example of parameters passed to this action."
        },
        "privilege_required": { "$ref": "#/definitions/StringDatatype" }
      },
      "required": ["id", "name", "action_type"]
    },
    "observable-definition": {
        "type": "object",
        "description": "Defines a type of data output (SCO) expected from the system.",
        "properties": {
            "id": { "$ref": "#/definitions/TokenDatatype" },
            "name": { "$ref": "#/definitions/StringDatatype" },
            "type": {
                "type": "string",
                "enum": ["cloud-api-call", "ai-model-output", "embedding-vector", "json-payload", "text"]
            },
            "schema": {
                "type": "object",
                "description": "JSON schema defining the structure of this observable."
            }
        },
        "required": ["id", "name", "type"]
    },
    "state-transition": {
      "type": "object",
      "properties": {
        "id": { "$ref": "#/definitions/TokenDatatype" },
        "action-id": {
          "$ref": "#/definitions/TokenDatatype",
          "description": "Reference to the system-action causing the transition."
        },
        "source-state-ids": {
          "type": "array",
          "items": { "$ref": "#/definitions/TokenDatatype" }
        },
        "target-state-id": { "$ref": "#/definitions/TokenDatatype" },
        "generated-observable-ids": {
            "type": "array",
            "items": { "$ref": "#/definitions/TokenDatatype" },
            "description": "References to observable-definitions produced by this transition."
        },
        "variable-changes": {
          "type": "array",
          "items": { "$ref": "#/definitions/condition" },
          "description": "Updates to state variables resulting from this transition."
        }
      },
      "required": ["id", "action-id", "target-state-id"]
    },
    "invariant": {
      "type": "object",
      "properties": {
        "id": { "$ref": "#/definitions/TokenDatatype" },
        "description": { "$ref": "#/definitions/MarkupMultilineDatatype" },
        "expression": { "$ref": "#/definitions/StringDatatype" },
        "criticality": { "type": "string", "enum": ["low", "moderate", "high", "critical"] }
      },
      "required": ["id", "description"]
    },
    "condition": {
      "type": "object",
      "properties": {
        "variable-id": { "$ref": "#/definitions/TokenDatatype" },
        "operator": { "type": "string", "enum": ["eq", "neq", "gt", "lt", "contains"] },
        "value": { "$ref": "#/definitions/StringDatatype" }
      },
      "required": ["variable-id", "operator", "value"]
    },
    "threat-landscape": {
      "type": "object",
      "properties": {
        "threat-actors": {
          "type": "array",
          "items": { "$ref": "#/definitions/threat-actor" }
        },
        "attack-techniques": {
          "type": "array",
          "items": { "$ref": "#/definitions/attack-technique" }
        }
      }
    },
    "threat-actor": {
      "type": "object",
      "properties": {
        "uuid": { "$ref": "#/definitions/UUIDDatatype" },
        "name": { "$ref": "#/definitions/StringDatatype" },
        "type": {
          "type": "string",
          "enum": ["insider", "competitor", "nation-state", "criminal", "hacktivist", "autonomous-agent", "misaligned-model", "m2m-process"]
        },
        "description": { "$ref": "#/definitions/MarkupMultilineDatatype" },
        "props": { "type": "array", "items": { "$ref": "#/definitions/property" } },
        "links": { "type": "array", "items": { "$ref": "#/definitions/link" } },
        "capabilities": {
          "type": "array",
          "items": { "$ref": "#/definitions/actor-capability" },
          "description": "Actor-specific capabilities that drive deduplication logic: pdr-modifier entries shift P/D/R weights on shared scenarios; reachability entries gate technique access. See §4.3.2 and §4.5."
        }
      },
      "required": ["uuid", "name", "type"]
    },
    "attack-technique": {
      "type": "object",
      "properties": {
        "uuid": { "$ref": "#/definitions/UUIDDatatype" },
        "technique-id": { "$ref": "#/definitions/StringDatatype" },
        "name": { "$ref": "#/definitions/StringDatatype" },
        "source": { "type": "string", "enum": ["MITRE ATT&CK", "MITRE ATLAS", "Custom", "CAPEC"] },
        "description": { "$ref": "#/definitions/MarkupMultilineDatatype" },
        "action_refs": {
            "type": "array",
            "items": { "$ref": "#/definitions/TokenDatatype" },
            "description": "The specific system-actions that constitute this attack pattern (e.g. a sequence of API calls)."
        },
        "props": { "type": "array", "items": { "$ref": "#/definitions/property" } }
      },
      "required": ["uuid", "technique-id", "name"]
    },
    "defense-landscape": {
      "type": "object",
      "properties": {
        "mitigations": {
          "type": "array",
          "items": { "$ref": "#/definitions/mitigation" }
        }
      }
    },
    "mitigation": {
      "type": "object",
      "properties": {
        "uuid": { "$ref": "#/definitions/UUIDDatatype" },
        "name": { "$ref": "#/definitions/StringDatatype" },
        "description": { "$ref": "#/definitions/MarkupMultilineDatatype" },
        "type": { "type": "string", "enum": ["protective", "detective", "responsive", "recovery"] },
        "control-implementation-refs": {
          "type": "array",
          "items": { "$ref": "#/definitions/UUIDDatatype" }
        }
      },
      "required": ["uuid", "name"]
    },
    "risk-analysis": {
      "type": "object",
      "properties": {
        "vulnerabilities": {
          "type": "array",
          "items": { "$ref": "#/definitions/vulnerability" }
        },
        "scenarios": {
          "type": "array",
          "items": { "$ref": "#/definitions/risk-scenario" }
        },
        "incidents": {
          "type": "array",
          "items": { "$ref": "#/definitions/incident" }
        }
      }
    },
    "vulnerability": {
      "type": "object",
      "properties": {
        "uuid": { "$ref": "#/definitions/UUIDDatatype" },
        "name": { "$ref": "#/definitions/StringDatatype" },
        "description": { "$ref": "#/definitions/MarkupMultilineDatatype" },
        "violated-invariant-id": { "$ref": "#/definitions/TokenDatatype" },
        "vulnerability_type": {
            "type": "string",
            "enum": ["forbidden-transition", "missing-transition", "unexpected-output"]
        }
      },
      "required": ["uuid", "name"]
    },
    "risk-scenario": {
      "type": "object",
      "properties": {
        "uuid": { "$ref": "#/definitions/UUIDDatatype" },
        "name": { "$ref": "#/definitions/StringDatatype" },
        "description": { "$ref": "#/definitions/MarkupMultilineDatatype" },
        "threat-actor-refs": { "type": "array", "items": { "$ref": "#/definitions/UUIDDatatype" } },
        "attack-technique-refs": { "type": "array", "items": { "$ref": "#/definitions/UUIDDatatype" } },
        "vulnerability-refs": { "type": "array", "items": { "$ref": "#/definitions/UUIDDatatype" } },
        "mitigation-refs": { "type": "array", "items": { "$ref": "#/definitions/UUIDDatatype" } },
        "metrics": {
          "type": "object",
          "properties": {
            "predicted-attacker-success-rate": { "$ref": "#/definitions/DecimalDatatype" },
            "actual-attacker-success-rate": { "$ref": "#/definitions/DecimalDatatype" },
            "predicted-defender-success-rate": { "$ref": "#/definitions/DecimalDatatype" },
            "actual-defender-success-rate": { "$ref": "#/definitions/DecimalDatatype" }
          }
        },
        "actor-capability-modifiers": {
          "type": "array",
          "items": { "$ref": "#/definitions/actor-capability-modifier" },
          "description": "Per-actor P/D/R weight overrides. Only emitted for actors whose capabilities produce non-baseline (≠1.0) weights for this scenario. Actors absent from this array are treated as baseline (1.0 on all dimensions). See §4.3.1 and §4.5."
        }
      },
      "required": ["uuid", "name"]
    },
    "incident": {
      "type": "object",
      "properties": {
        "uuid": { "$ref": "#/definitions/UUIDDatatype" },
        "title": { "$ref": "#/definitions/MarkupLineDatatype" },
        "description": { "$ref": "#/definitions/MarkupMultilineDatatype" },
        "links": { "type": "array", "items": { "$ref": "#/definitions/link" } }
      },
      "required": ["uuid", "title"]
    },
    "actor-capability": {
      "title": "Actor Capability",
      "description": "Describes a single capability possessed by a threat actor that either shifts P/D/R weights on a shared attack-path scenario (affects: prevention|detection|response) or gates access to specific techniques the actor can reach that others cannot (affects: reachability). Used by the generator to avoid the cartesian product anti-pattern — see §4.3.2 and §4.4.",
      "type": "object",
      "properties": {
        "id": {
          "$ref": "#/definitions/TokenDatatype",
          "description": "Stable identifier for this capability within the actor record (e.g. 'zero-day-cred-access', 'opsec-discipline')."
        },
        "affects": {
          "type": "string",
          "enum": ["prevention", "detection", "response", "reachability"],
          "description": "The dimension this capability modifies. 'reachability' does not carry a numeric modifier; use 'unlocks' to enumerate the technique IDs it makes accessible."
        },
        "modifier": {
          "$ref": "#/definitions/DecimalDatatype",
          "description": "Additive delta applied to the baseline P/D/R weight (1.0) for affects ∈ {prevention, detection, response}. Negative values degrade the defense (e.g. -0.40 means effective prevention weight = 0.60). Ignored when affects = 'reachability'. Example values are tabulated in §4.5."
        },
        "unlocks": {
          "type": "array",
          "items": { "$ref": "#/definitions/StringDatatype" },
          "description": "For affects = 'reachability': MITRE ATT&CK or ATLAS technique IDs this capability makes accessible. Example: insider 'knowledge-of-naming-conventions' unlocks T1036.010 without the enumeration prerequisite edge. Omitted for P/D/R affects types."
        },
        "excludes": {
          "type": "array",
          "items": { "$ref": "#/definitions/StringDatatype" },
          "description": "Technique IDs this actor structurally cannot use. The generator calls actor_can_use() and returns False for these. Example: autonomous-agent/misaligned-model cannot use T1621 (MFA fatigue) — no human target. See §4.2 and §4.5."
        },
        "rationale": { "$ref": "#/definitions/MarkupMultilineDatatype" }
      },
      "required": ["id", "affects"]
    },
    "actor-capability-modifier": {
      "title": "Actor Capability Modifier",
      "description": "Encodes the per-actor P/D/R weight overrides for a specific risk-scenario. Emitted only when the actor's capabilities produce at least one non-baseline (≠1.0) weight. Actors absent from the scenario's actor-capability-modifiers array are implicitly treated as baseline 1.0 on all three dimensions. Modifiers are multipliers: effective_weight = baseline × modifier. See §4.3.1.",
      "type": "object",
      "properties": {
        "actor-ref": {
          "$ref": "#/definitions/UUIDDatatype",
          "description": "UUID of the threat-actor this modifier applies to."
        },
        "pdr-weights": {
          "type": "object",
          "description": "Multipliers applied to the scenario's baseline P/D/R defense effectiveness for this actor. A value of 1.0 is baseline (omit if baseline to avoid noise). Values below 1.0 indicate the actor makes the defense less effective (e.g., nation-state OPSEC discipline sets detection = 0.40). Values above 1.0 are valid but unusual.",
          "properties": {
            "prevention": { "$ref": "#/definitions/DecimalDatatype" },
            "detection":  { "$ref": "#/definitions/DecimalDatatype" },
            "response":   { "$ref": "#/definitions/DecimalDatatype" }
          }
        },
        "rationale": {
          "$ref": "#/definitions/MarkupMultilineDatatype",
          "description": "Human-readable explanation of why this actor's capabilities shift the weights. Example: 'Nation-state zero-day credential access bypasses preventive controls that rely on known-credential detection; effective prevention weight reduced by 0.40 per §4.5 reference table.'"
        }
      },
      "required": ["actor-ref", "pdr-weights"]
    },
    "import-definition": {
      "type": "object",
      "properties": {
        "href": { "$ref": "#/definitions/URIReferenceDatatype" },
        "rel": { "type": "string", "enum": ["ssp", "component-definition", "system-model"] }
      },
      "required": ["href"]
    },
    "metadata": {
      "title": "Document Metadata",
      "description": "Provides information about the containing document, and defines concepts that are shared across the document.",
      "type": "object",
      "properties": {
        "title": { "$ref": "#/definitions/MarkupLineDatatype" },
        "published": { "$ref": "#/definitions/DateTimeWithTimezoneDatatype" },
        "last-modified": { "$ref": "#/definitions/DateTimeWithTimezoneDatatype" },
        "version": { "$ref": "#/definitions/StringDatatype" },
        "oscal-version": { "$ref": "#/definitions/StringDatatype" },
        "revisions": {
          "type": "array",
          "minItems": 1,
          "items": {
            "title": "Revision History Entry",
            "type": "object",
            "properties": {
              "title": { "$ref": "#/definitions/MarkupLineDatatype" },
              "published": { "$ref": "#/definitions/DateTimeWithTimezoneDatatype" },
              "last-modified": { "$ref": "#/definitions/DateTimeWithTimezoneDatatype" },
              "version": { "$ref": "#/definitions/StringDatatype" },
              "oscal-version": { "$ref": "#/definitions/StringDatatype" },
              "props": { "type": "array", "items": { "$ref": "#/definitions/property" } }
            },
            "required": ["version"]
          }
        },
        "document-ids": { "type": "array", "items": { "$ref": "#/definitions/document-id" } },
        "props": { "type": "array", "items": { "$ref": "#/definitions/property" } },
        "links": { "type": "array", "items": { "$ref": "#/definitions/link" } },
        "roles": { "type": "array", "items": { "$ref": "#/definitions/role" } },
        "parties": { "type": "array", "items": { "$ref": "#/definitions/party" } }
      },
      "required": ["title", "last-modified", "version", "oscal-version"]
    },
    "property": {
      "title": "Property",
      "type": "object",
      "properties": {
        "name": { "$ref": "#/definitions/TokenDatatype" },
        "uuid": { "$ref": "#/definitions/UUIDDatatype" },
        "ns": { "$ref": "#/definitions/URIDatatype" },
        "value": { "$ref": "#/definitions/StringDatatype" },
        "class": { "$ref": "#/definitions/TokenDatatype" }
      },
      "required": ["name", "value"]
    },
    "link": {
      "title": "Link",
      "type": "object",
      "properties": {
        "href": { "$ref": "#/definitions/URIReferenceDatatype" },
        "rel": { "$ref": "#/definitions/TokenDatatype" },
        "media-type": { "$ref": "#/definitions/StringDatatype" },
        "text": { "$ref": "#/definitions/MarkupLineDatatype" }
      },
      "required": ["href"]
    },
    "role": {
      "title": "Role",
      "type": "object",
      "properties": {
        "id": { "$ref": "#/definitions/TokenDatatype" },
        "title": { "$ref": "#/definitions/MarkupLineDatatype" },
        "short-name": { "$ref": "#/definitions/StringDatatype" },
        "description": { "$ref": "#/definitions/MarkupMultilineDatatype" }
      },
      "required": ["id", "title"]
    },
    "party": {
      "title": "Party",
      "type": "object",
      "properties": {
        "uuid": { "$ref": "#/definitions/UUIDDatatype" },
        "type": { "type": "string", "enum": ["person", "organization"] },
        "name": { "$ref": "#/definitions/StringDatatype" }
      },
      "required": ["uuid", "type"]
    },
    "document-id": {
      "title": "Document Identifier",
      "type": "object",
      "properties": {
        "scheme": { "$ref": "#/definitions/URIDatatype" },
        "identifier": { "$ref": "#/definitions/StringDatatype" }
      },
      "required": ["identifier"]
    },
    "back-matter": {
      "title": "Back matter",
      "description": "A collection of resources that may be referenced from within the OSCAL document instance.",
      "type": "object",
      "properties": {
        "resources": {
          "type": "array",
          "items": {
            "title": "Resource",
            "type": "object",
            "properties": {
              "uuid": { "$ref": "#/definitions/UUIDDatatype" },
              "title": { "$ref": "#/definitions/MarkupLineDatatype" },
              "description": { "$ref": "#/definitions/MarkupMultilineDatatype" },
              "rlinks": {
                "type": "array",
                "items": {
                  "title": "Resource link",
                  "type": "object",
                  "properties": {
                    "href": { "$ref": "#/definitions/URIReferenceDatatype" },
                    "media-type": { "$ref": "#/definitions/StringDatatype" }
                  },
                  "required": ["href"]
                }
              }
            },
            "required": ["uuid"]
          }
        }
      }
    },
    "UUIDDatatype": {
      "type": "string",
      "pattern": "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[45][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
    },
    "TokenDatatype": {
      "type": "string",
      "pattern": "^(\\p{L}|_)(\\p{L}|\\p{N}|[.\\-_])*$"
    },
    "StringDatatype": {
      "type": "string",
      "pattern": "^\\S(.*\\S)?$"
    },
    "MarkupLineDatatype": {
      "type": "string",
      "pattern": "^[^\n]+$"
    },
    "MarkupMultilineDatatype": {
      "type": "string"
    },
    "URIDatatype": {
      "type": "string",
      "format": "uri"
    },
    "URIReferenceDatatype": {
      "type": "string",
      "format": "uri-reference"
    },
    "DateTimeWithTimezoneDatatype": {
      "type": "string",
      "format": "date-time"
    },
    "DecimalDatatype": {
      "type": "number"
    }
  },
  "oneOf": [
    {
      "properties": {
        "threat-model": {
          "$ref": "#/definitions/threat-model"
        }
      },
      "required": ["threat-model"]
    }
  ]
}
```

---

## 4. Actor-Centric Attack Path Deduplication

### 4.1 Problem: Cartesian Product Anti-Pattern

The naive generator creates scenarios as a cartesian product: `N actors × M techniques = N×M scenarios`, each with a single entry in `threat-actor-refs`. This is wrong.

The **attack path** is defined by the technique and the system state it exploits. Whether a criminal, nation-state, or misaligned agent walks T1078 (Valid Accounts), the path through the system state graph is identical. Generating three separate scenarios for the same path produces redundant risk analysis, inflates scenario counts, and obscures meaningful differentiation.

**Correct model**: one scenario per attack path (technique or technique chain), with `threat-actor-refs` listing all actors who can execute it. Actor-specific capability differences are captured as `actor-capability-modifiers` on the shared scenario — they shift P/D/R weights but do not create new paths unless the actor has access to genuinely different system states.

### 4.2 When an Actor Warrants a Separate Path

A separate scenario is only justified when an actor brings a capability that materially changes the graph structure — specifically:

1. **Different entry state (access position)**: The actor enters the attack graph at a different node, bypassing phases other actors must traverse.
   - Insider: already authenticated; skips Initial Access; enters at Privilege Escalation or Persistence directly. T1087 (Account Discovery) requires no credential theft prerequisite.
   - Nation-state: supply chain or pre-positioned access may enter at a state that bypasses CloudTrail (compromised logging pipeline is a different entry state node).
   - Misaligned agent: holds API credentials scoped to its service role; can invoke IAM actions via its own service principal without external credential theft (unique path for T1098.001).

2. **Technique availability gated by actor**: Some techniques are structurally unavailable to certain actors.
   - T1621 (MFA Request Generation / fatigue): not available to misaligned agent — no human target to fatigue.
   - T1556.009 (Conditional Access Bypass): requires IAM-level write access; nation-state and insider have higher reachability; external criminal typically does not.
   - T1036.010 (Masquerade Account Name): insider knows naming convention directly; external actors must enumerate it first (different prerequisite edge).

3. **P/D/R weight shift only (same path, different weights)**: Most actor differentiation belongs here — the path is the same but edge weights differ based on actor capability. This is not a new scenario; it is an `actor-capability-modifier` on the existing scenario.

### 4.3 Required Schema Additions

#### 4.3.1 `actor-capability-modifier` (new object definition)

Added to `risk-scenario` as an optional array. Emitted only when an actor's capability produces a non-baseline P/D/R weight.

```json
"actor-capability-modifier": {
  "type": "object",
  "properties": {
    "actor-ref": { "$ref": "#/definitions/UUIDDatatype" },
    "pdr-weights": {
      "type": "object",
      "properties": {
        "prevention": { "$ref": "#/definitions/DecimalDatatype" },
        "detection":  { "$ref": "#/definitions/DecimalDatatype" },
        "response":   { "$ref": "#/definitions/DecimalDatatype" }
      },
      "description": "Multipliers applied to baseline P/D/R values for this actor. 1.0 = baseline. Values < 1.0 indicate the actor makes the defense less effective."
    },
    "rationale": { "$ref": "#/definitions/MarkupMultilineDatatype" }
  },
  "required": ["actor-ref", "pdr-weights"]
}
```

Updated `risk-scenario` to include:
```json
"actor-capability-modifiers": {
  "type": "array",
  "items": { "$ref": "#/definitions/actor-capability-modifier" },
  "description": "Per-actor P/D/R weight overrides. Only emitted for actors whose capabilities produce non-baseline weights."
}
```

#### 4.3.2 `capabilities` array on `threat-actor`

Drives deduplication logic in the generator. Two capability types: `pdr-modifier` (affects weights on shared path) and `access-position` (may unlock a distinct entry state, warranting a new path).

```json
"actor-capability": {
  "type": "object",
  "properties": {
    "id":       { "$ref": "#/definitions/TokenDatatype" },
    "affects":  { "type": "string", "enum": ["prevention", "detection", "response", "reachability"] },
    "modifier": { "$ref": "#/definitions/DecimalDatatype",
                  "description": "For pdr affects: additive delta applied to baseline weight. For reachability: ignored." },
    "unlocks":  { "type": "array", "items": { "$ref": "#/definitions/StringDatatype" },
                  "description": "For reachability: technique IDs this capability makes accessible to the actor." }
  },
  "required": ["id", "affects"]
}
```

`threat-actor` gains:
```json
"capabilities": {
  "type": "array",
  "items": { "$ref": "#/definitions/actor-capability" }
}
```

### 4.4 Generator Logic

Replace the cartesian product loop with a technique-centric loop:

```python
for technique in techniques:
    eligible_actors = [a for a in actors if actor_can_use(a, technique)]
    if not eligible_actors:
        continue
    modifiers = [
        capability_modifier(a, technique)
        for a in eligible_actors
        if has_non_baseline_capability(a, technique)
    ]
    scenarios.append(build_scenario(eligible_actors, technique, modifiers))
```

- `actor_can_use(actor, technique)`: returns `False` if the technique requires access or conditions the actor structurally cannot satisfy (e.g., T1621 for `autonomous-agent` / `misaligned-model` types).
- `has_non_baseline_capability(actor, technique)`: returns `True` only when the actor's capabilities produce a P/D/R modifier that differs from 1.0 for this technique.
- `build_scenario(actors, technique, modifiers)`: emits one scenario with `threat-actor-refs` listing all eligible actors and `actor-capability-modifiers` for those with non-baseline weights.

This collapses `N×M` scenarios to `M` (or fewer, where some actors cannot use a technique), with per-actor P/D/R differentiation preserved in the modifier array.

### 4.5 Actor Capability Reference Table (AC-2 / IAM Domain)

| Actor | Type | Capability | Affects | P modifier | D modifier | R modifier |
|---|---|---|---|---|---|---|
| Nation-State | `nation-state` | Zero-day credential access | prevention | -0.40 | — | — |
| Nation-State | `nation-state` | OPSEC discipline | detection | — | -0.60 | — |
| Nation-State | `nation-state` | Supply chain pre-position | reachability | — | — | — |
| Misaligned Agent | `autonomous-agent` | Machine-speed API replay | detection | — | -0.70 | — |
| Misaligned Agent | `autonomous-agent` | Automated re-entry | response | — | — | -0.50 |
| Insider | `insider` | Legitimate credential possession | prevention | -0.30 | -0.40 | — |
| Insider | `insider` | Knowledge of naming conventions | reachability (T1036.010 prereq skipped) | — | — | — |
| Criminal | `criminal` | Baseline external attacker | — | 1.0 | 1.0 | 1.0 |

Technique availability gates:
- T1621 (MFA fatigue): not available to `autonomous-agent`, `misaligned-model`, `m2m-process`
- T1556.009 (Conditional Access Bypass): not available to `criminal` (requires IAM write; external attacker assumed not to have it without prior privilege escalation)
- T1036.010 (Masquerade Account Name): insider skips enumeration prerequisite edge
```
