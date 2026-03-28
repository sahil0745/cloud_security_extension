# Extension Assets

This folder contains the icons and animations for the Cloud Misconfiguration Security Extension.

## Required Icons
To publish to the Chrome Web Store, you will need to add the following icons to this folder:
- `icon16.png`
- `icon48.png`
- `icon128.png`

### Platform Detection Icons (Step 2)
To enable the dynamic platform badge in the popup, you must add the following icons to this folder:
- `aws.png`
- `azure.png`
- `gcp.png`

Once added, update the `manifest.json` file to include the `"icons"` property:
```json
"icons": {
  "16": "assets/icons/icon16.png",
  "48": "assets/icons/icon48.png",
  "128": "assets/icons/icon128.png"
}
```
