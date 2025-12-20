# Ransom-ISAC L.O.C.K. S.T.A.R. Blog Contribution Guidelines

## Overview

The **L.O.C.K. S.T.A.R.** (Level of Critical Knowledge in Specialized Techniques on Advancements and Research) initiative is Ransom-ISAC's framework for recognizing ransomware researchers and practitioners who contribute high-quality threat intelligence through their blogging program. Contributors teach novel workflows that bridge the gap between actionable knowledge sharing and partially shared intelligence.

This document provides comprehensive formatting and style guidelines for creating L.O.C.K. S.T.A.R.-eligible blog content for publication on the Ransom-ISAC platform.

---

## ⚠️ Important Notice

**Failure to adhere to these reporting standards may result in rejection of your L.O.C.K. S.T.A.R. candidacy.**

All submissions undergo rigorous review by a network of subject-matter experts across the ransomware defense community. Reviewers include seasoned threat intelligence analysts, incident responders, malware researchers, and blockchain forensics specialists. Because your work will be evaluated by leading practitioners in the field, the standard for publication must be exceptionally high.

Submissions that do not meet these formatting and quality requirements will be returned for revision or rejected outright.

---

## Platform Requirement: Notion

**All blog drafts must be authored in Notion** with proper header management before submission. Notion serves as the collaborative drafting and editing platform for L.O.C.K. S.T.A.R. content.

---

## Document Structure

### Required Metadata Header

Every blog post must begin with structured metadata:

| Element | Description | Example |
|---------|-------------|---------|
| **Category** | Primary classification | `Threat Intelligence`, `Infrastructure`, `DFIR`, `Reverse Engineering` |
| **Read Time** | Estimated reading duration | `45 min read`, `60 min read` |
| **Publication Date** | Target or actual date | `October 20, 2025` |
| **Tags** | Relevant topic tags | `Reverse Engineering`, `DFIR`, `Malware Analysis`, `Blockchain` |
| **Author** | Primary author name | `Jane Mitchell` *(example)* |
| **Contributors** | Additional contributors | `Carlos Mendez, Aisha Patel, Marcus Chen` *(example)* |

**Example Metadata Block:**
```
Category: Threat Intelligence
Read Time: 45 min read
Publication Date: October 20, 2025
Tags: Reverse Engineering, DFIR, Malware Analysis, Blockchain

Author: Jane Mitchell

Contributors: Carlos Mendez, Aisha Patel, Marcus Chen, David O'Brien
```

### Header Hierarchy

Use proper Notion heading levels consistently:

- **H1** (`#`): Article title only (one per document)
- **H2** (`##`): Major sections
- **H3** (`###`): Subsections within major sections
- **H4** (`####`): Sub-subsections for detailed breakdowns

**Example Document Structure:**
```
# Cross-Chain TxDataHiding Crypto Heist: A Very Chainful Process (Part 1)

## How it Works
### 1. Smart Contract Storage Hiding
### 2. Transaction Data Hiding (TxDataHiding)
### 3. Cross-Chain TxDataHiding

## Full Attack Chain

## DPRK Fake Job Social Engineering Campaign
### Headhunt
### The Interview

## Initial Multi-Payload Stager
### Obfuscation
### Payload Retrieval Summary

## Conclusion
## Resources & Detection Tooling
## Acknowledgments
## Indicators of Compromise
## YARA Rules
```

*The above is an example structure from a published Ransom-ISAC threat intelligence report.*

---

## Technical Content Formatting

### Code Formatting: IPs, URLs, Domains, and Hashes

**CRITICAL REQUIREMENT:** All technical indicators must be formatted as inline code or code blocks.

#### Inline Code (Single Items)

Use backticks for individual indicators within prose:

**Example Indicator Formatting:**

| Type | Format | Example |
|------|--------|---------|
| **IP Address** | `` `IP` `` | `23.27.20.143` |
| **Domain** | `` `domain` `` | `bsc-dataseed.binance.org` |
| **URL** | `` `URL` `` | `https://api.trongrid.io/v1/accounts/` |
| **File Hash (SHA256)** | `` `hash` `` | `16df15306f966ae5c5184901747a32087483c03eebd7bf19dbfc38e2c4d23ff8` |
| **File Hash (MD5)** | `` `hash` `` | `A7F3D8E2` |
| **Transaction Hash** | `` `hash` `` | `0xf46c86c886bbf9915f4841a8c27b38c519fe3ce54ba69c98d233d0ffc94d19fc` |
| **Wallet Address** | `` `address` `` | `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` |
| **File Path** | `` `path` `` | `/mnt/user-data/uploads/` |
| **XOR Key** | `` `key` `` | `'2[gWfGj;<:-93Z^C'` |

*The above are examples. Apply this formatting to all technical indicators in your submission.*

#### Defanged Indicators (for Malicious Content)

When documenting malicious infrastructure, defang indicators to prevent accidental access:

**Example Defanging Conventions:**

| Type | Original | Defanged |
|------|----------|----------|
| **URL** | `http://23.27.20.143:27017/$/boot` | `hxxp://23[.]27[.]20[.]143:27017/$/boot` |
| **Domain** | `malicious-domain.com` | `malicious-domain[.]com` |
| **IP** | `136.0.9.8` | `136[.]0[.]9[.]8` |

**Example Usage in Text:**
> The payload fetches data via `hxxp://23[.]27[.]20[.]143:27017/$/boot` using custom headers.

*Always defang malicious indicators to prevent accidental navigation or execution.*

### Code Blocks

Use fenced code blocks with language specification for:

**Example API Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "eth_getTransactionByHash",
  "params": ["0xf46c86c886bbf9915f4841a8c27b38c519fe3ce54ba69c98d233d0ffc94d19fc"],
  "id": 1
}
```

**Example Shell Command:**
```bash
python ooxml/scripts/unpack.py <office_file> <output_directory>
```

**Example Python Code:**
```python
def xor_decrypt(data, key):
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ ord(key[i % len(key)])
    return result
```

**Example JavaScript Code:**
```javascript
const payload = await fetch(url, {
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Sec-V': _V || 0
  }
});
```

*Always specify the language after the opening fence (```python, ```javascript, ```json, etc.) for proper syntax highlighting.*

**Example YARA Rule:**
```yara
rule DPRKObfuscatedJavaScript1 {
    meta:
        description = "RepoCrossChainTxDataHiding detection"
        author = "Ransom-ISAC"

    strings:
        $s1 = "global['_V']"
        $s2 = "global['r']"

    condition:
        filesize < 50KB and all of ($s*)
}
```

*The above is an example. Include detection rules specific to the threats documented in your research.*

---

## Images and Figures

### Image Quality Requirements

**CRITICAL:** All images must be clear, high-resolution, and use the highest quality filetype available.

| Requirement | Standard |
|-------------|----------|
| **Resolution** | Minimum 150 DPI; 300 DPI preferred for diagrams |
| **Format** | PNG for screenshots and diagrams; SVG for vector graphics where possible |
| **Clarity** | Text within images must be legible at 100% zoom |
| **Compression** | Avoid lossy compression (JPEG) for screenshots with text |
| **File Size** | Balance quality with reasonable file size; do not over-compress |

**Professionalism Standard:** Format all visual content as if you are presenting to executive leadership or publishing in a peer-reviewed journal. This content will be public-facing and represents both your expertise and the Ransom-ISAC brand. Blurry screenshots, poorly cropped images, or low-resolution diagrams will result in revision requests or rejection.

### Image Placement

Images should be:
1. Placed immediately after the relevant descriptive text
2. Referenced in prose before appearing
3. Appropriately sized (not exceeding page width)

### Centered Captions

**CRITICAL REQUIREMENT:** All images must have centered captions that describe the content.

**Example Format in Notion:**
```
[Image]

*Figure description explaining what the image shows*
```

**Example Captions (from published Ransom-ISAC blogs):**

> ![Etherhiding example showing smart contract storage hiding technique]
> 
> *Etherhiding example showing smart contract storage hiding technique*

> ![Step-by-step diagram of Cross-Chain TxDataHiding attack flow]
> 
> *Step-by-step diagram of Cross-Chain TxDataHiding attack flow*

> ![VirusTotal detection results showing 5 security vendors flagged the file]
> 
> *VirusTotal detection results showing 5 security vendors flagged the file*

*The above are examples of properly captioned images. Ensure all figures in your submission follow this format.*

### Caption Style Guidelines

- Use sentence case (capitalize first word only, unless proper nouns)
- Be descriptive but concise
- Include context that helps the reader understand significance
- For screenshots of tools, include the tool name
- For diagrams, describe what the diagram illustrates

### Professional Presentation Standards

Remember: **This content will be publicly accessible and reviewed by industry experts.**

**Do:**
- Crop images to remove unnecessary whitespace or desktop clutter
- Ensure consistent styling across all figures (fonts, colours, borders)
- Use annotations (arrows, boxes, highlights) to draw attention to key elements
- Redact any sensitive information (personal data, internal IPs, etc.)
- Test that all images render correctly before submission

**Do Not:**
- Include desktop wallpaper, browser bookmarks, or personal information in screenshots
- Use inconsistent image sizes or aspect ratios
- Submit blurry, pixelated, or stretched images
- Leave visible cursor artifacts or selection highlights (unless intentional)
- Use images with watermarks from other sources

### MITRE ATT&CK Mapping

For more sophisticated campaigns, it is **highly encouraged** to include MITRE ATT&CK technique mapping with visual representation.

**Recommended Tool:** Use **Flowviz** for creating professional attack flow visualisations mapped to MITRE ATT&CK.

> **GitHub:** [https://github.com/davidljohnson/flowviz](https://github.com/davidljohnson/flowviz)

Flowviz enables you to:
- Create clear, professional attack chain diagrams
- Map each stage to specific MITRE ATT&CK techniques (e.g., `T1059.007`, `T1027`, `T1571`)
- Generate consistent, publication-ready visualisations
- Export high-quality images suitable for L.O.C.K. S.T.A.R. submissions

**Example MITRE Mapping Table (to accompany Flowviz diagrams):**

| Stage | Technique ID | Technique Name | Description |
|-------|--------------|----------------|-------------|
| Initial Access | T1566.002 | Spearphishing Link | Malicious GitHub repository link via LinkedIn/Telegram |
| Execution | T1059.007 | JavaScript | Obfuscated JS payload execution via Node.js |
| Defence Evasion | T1027 | Obfuscated Files | Multi-layer XOR and character shuffling |
| C2 | T1571 | Non-Standard Port | Communication over port 27017 |
| Exfiltration | T1041 | Exfiltration Over C2 | Data sent to attacker infrastructure |

*The above is an example. Include technique mappings relevant to your documented threat.*

Including MITRE ATT&CK mappings demonstrates analytical rigour and enables defenders to operationalise your research within their detection frameworks.

---

## Tables

### Indicators of Compromise Table

**Required format for IOC sections:**

**Example IOC Table:**

| Type | Indicator |
|------|-----------|
| Initial Payload (SHA256) | `16df15306f966ae5c5184901747a32087483c03eebd7bf19dbfc38e2c4d23ff8` |
| TRON Wallet (Index 1) | `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` |
| BSC Transaction Hash | `0xf46c86c886bbf9915f4841a8c27b38c519fe3ce54ba69c98d233d0ffc94d19fc` |
| C2 Server | `23[.]27[.]20[.]143:27017` |
| C2 Endpoint | `/$/boot` |

*The above is an example. Replace with your actual indicators of compromise.*

### Attack Flow/Summary Tables

**Example Attack Flow Table:**

| Step | Component | Action | Result |
|------|-----------|--------|--------|
| 1 | Initial Stager | Executes obfuscated IIFE | Deobfuscates strings |
| 2 | Blockchain Query | Queries TRON API | Retrieves BSC hash |
| 3 | Payload Fetch | Queries BSC RPC | Extracts encrypted payload |
| 4 | Execution | XOR decrypt + eval() | Runs malicious code |

*The above is an example. Adapt the structure to match your specific attack chain.*

### Capability/Feature Tables

**Example Capability Summary Table:**

| Category | Count | Notes |
|----------|-------|-------|
| Browsers Supported | 10+ | Chrome, Firefox, Edge, Brave, Opera, etc. |
| Wallet Extensions | 60+ | MetaMask, Phantom, Trust, Coinbase, etc. |
| Password Managers | 10+ | 1Password, LastPass, Bitwarden, etc. |

*The above is an example. Use this format to summarize malware capabilities, infrastructure scope, or other quantifiable findings.*

---

## Content Sections

### Required Sections for Technical Analysis Posts

1. **Introduction/Overview**
   - Context of the investigation
   - Key findings summary
   - Attribution notes (if applicable)

2. **Technical Analysis**
   - Detailed breakdown of functionality
   - Code analysis with snippets
   - Obfuscation/anti-analysis techniques

3. **Attack Chain/Kill Chain**
   - Step-by-step flow diagram
   - Component relationships
   - Persistence mechanisms

4. **Indicators of Compromise**
   - Formatted table of all indicators
   - File hashes, IPs, domains, wallet addresses

5. **Detection & Mitigation**
   - YARA rules
   - Sigma rules (if applicable)
   - EDR/SIEM detection queries
   - Defensive recommendations

6. **Conclusion**
   - Summary of key findings
   - Broader implications
   - Call to action for defenders

7. **Acknowledgments**
   - Credit to contributors
   - Partner organizations

8. **Resources**
   - GitHub repository links
   - External references
   - Tools mentioned

### Multi-Part Series

For extensive research spanning multiple articles:

- Use consistent naming: `Part 1`, `Part 2`, `Part 3`, etc.
- Include "What's Next" section previewing subsequent parts
- Link to previous parts at the beginning
- Provide brief recap of relevant prior findings

---

## Writing Style

### Tone

- **Professional yet accessible**: Technical accuracy without unnecessary jargon
- **Authoritative**: Confident assertions backed by evidence
- **Educational**: Explain concepts for readers who may not be experts in all domains
- **Collaborative**: Acknowledge uncertainty where appropriate

### Attribution Language

When discussing threat actors:

**Do:**
- "We assess with moderate confidence..."
- "Attribution indicators suggest..."
- "Consistent with DPRK-linked operations..."
- "The targeting patterns strongly suggest..."

**Avoid:**
- Definitive attribution without evidence
- Speculation presented as fact

### Technical Accuracy

- **Verify all hashes** before publication
- **Test all code snippets** for accuracy
- **Confirm IOCs** are correctly formatted
- **Validate external links** are accessible

---

## Linking and References

### External Links

Format as descriptive hyperlinks:

**Example:**
> Similar reports include [DeceptiveDevelopment, reported in September 2025](https://www.eset.com/...) utilising the ClickFix campaign.

*Always use descriptive link text rather than raw URLs in prose.*

### Internal Cross-References

Reference other sections clearly:

**Examples:**
> As detailed in Part 1, the attack operates through a sophisticated 10-stage process...

> See the **"Obfuscation Techniques"** section for detailed analysis.

### GitHub Repository Links

Always link to detection resources:

**Example:**
> **GitHub Repository:** [https://github.com/Ransom-ISAC-Org/LOCKSTAR]([https://github.com/Your-Org/Detection-Rules](https://github.com/Ransom-ISAC-Org/LOCKSTAR))

*Include links to any detection rules, scripts, or resources you've published alongside your research.*

---

## Special Formatting

### Key Distinctions / Callout Boxes

Use bold headers with bullet points for important distinctions:

**Example Key Distinction Block:**

**Key Distinction:**
- **Etherhiding** = Smart contract **storage-based**
- **TxDataHiding** = Transaction **data-based**  
- **Cross-Chain TxDataHiding** = Multi-blockchain **indexing system**

*Use this format to highlight critical technical differences or key takeaways.*

### Warning/Note Callouts

For critical warnings:

**Example Warning:**
> **Note: Do not run this code!**
> 
> The following script is provided for educational purposes only...

**Example Risk Callout:**
> **Critical Risk:** The combination of VSCode injection and JavaScript's cross-platform nature makes this particularly dangerous.

*Use callouts sparingly to highlight genuinely critical information.*

### Step-by-Step Workflows

Number major steps and use lettering for sub-steps:

**Example Step-by-Step Breakdown:**

**1. Initial Execution**
   Malicious JavaScript file executes from weaponised repository.

**2. String Deobfuscation**
   Custom character-shuffling algorithm decodes scrambled strings.
   
   a. Mathematical swapping with numeric key
   b. Reveals blockchain addresses and XOR keys

**3. First Payload Retrieval**
   a. Query TRON blockchain API
   b. Extract transaction data field
   c. Convert HEX to UTF-8
   d. Reverse string to obtain BSC transaction hash

*Use this format to document attack chains, analysis workflows, or procedural guidance.*

---

## Quality Checklist

Before submission, verify:

- [ ] All IPs, URLs, domains, and hashes are in `code format`
- [ ] Malicious indicators are properly defanged
- [ ] All images have centered, descriptive captions
- [ ] Headers follow proper hierarchy (H1 → H2 → H3 → H4)
- [ ] IOC table is complete and properly formatted
- [ ] Code blocks have language specification
- [ ] External links are working
- [ ] YARA/detection rules have been tested
- [ ] Contributors are properly acknowledged
- [ ] Metadata header is complete

---

## Submission Process

1. **Draft in Notion** following these guidelines
2. **Share with Ransom-ISAC editors** for review
3. **Incorporate feedback** and revisions
4. **Final approval** for publication
5. **Publication** on ransom-isac.org/blog/

---

## Contact

For questions about the L.O.C.K. S.T.A.R. program or submission guidelines:

**Email:** contact@ransom-isac.org

**Apply for L.O.C.K. S.T.A.R.:** [https://ransom-isac.org/lockstar-members/application/](https://ransom-isac.org/lockstar-members/application/)

---

*These guidelines are based on analysis of published Ransom-ISAC blog content and the L.O.C.K. S.T.A.R. initiative requirements.*
