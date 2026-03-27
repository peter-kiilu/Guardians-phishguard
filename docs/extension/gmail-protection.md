# Gmail Protection

The second critical component of PhishGuard is the internal email scanner, handled exclusively by `gmail_content.js`.

## Mutation Observer

Because modern Gmail is a Single Page Application (SPA), traditional page reloads don't frequently occur. `gmail_content.js` deploys a native `MutationObserver` targeting the specific parent table elements inside the Gmail inbox interface.

Whenever a user opens an email or a new email arrives in the inbox list, the script isolates and reads the following obfuscated DOM classes:

- Sender Name & Email (`span.zF`)
- Subject Line (`span.bog`)
- Email Snippet (`span.y2`)

## The Analytics Flow

1. **Local Phishing Dictionary**: 
   The snippet and subject text are run against an internal library of 65+ recognized urgency phrases ("verify your account", "will be closed within 24 hours").
2. **Mismatched Link Detection**:
   The script crawls `href` anchor elements looking for disparities between the **visual displayed text** and the actual domain redirect.
3. **Backend Offload**:
   If the internet is available, the content is securely transmitted to `/analyze-email`.
   
## Visual UI Injection

If a threat is detected, `gmail_content.js` aggressively resizes the target row with DOM injection (`gmail_styles.css`):

- Embeds a thick **Red Border** around the fraudulent email.
- Appends a dynamically created **"⚠ Phishing Risk"** badge adjacent to the subject line.
- Implements a precise hover-state tooltip describing the exact ML response and the heuristics detected, enabling users to understand *why* the message was flagged.
