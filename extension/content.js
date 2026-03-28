// Content script injected into AWS, Azure, GCP consoles
console.log("CloudSec Content Script loaded.");

// Monitor DOM for configuration changes (simplified example)
const observer = new MutationObserver((mutations) => {
  for (let mutation of mutations) {
    if (mutation.type === 'childList' || mutation.type === 'attributes') {
      // In a real scenario, we would parse specific DOM elements or intercept XHR/Fetch requests
      // to detect configuration changes like making an S3 bucket public.
      
      // Example: Detect if a "Save" button was clicked on a permissions page
      if (mutation.target.innerText && mutation.target.innerText.includes("Public access")) {
         const payload = {
           provider: window.location.hostname.includes("aws") ? "AWS" : 
                     window.location.hostname.includes("azure") ? "Azure" : "GCP",
           action: "PERMISSION_CHANGE",
           resource: "detected-resource",
           timestamp: new Date().toISOString()
         };
         
         chrome.runtime.sendMessage({
           type: "CONFIG_CHANGE_DETECTED",
           payload: payload
         });
      }
    }
  }
});

observer.observe(document.body, { childList: true, subtree: true, attributes: true });
