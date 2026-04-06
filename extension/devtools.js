/**
 * devtools.js
 *
 * Runs inside the invisible DevTools page (devtools.html).
 * Registers the "Defender XRay" panel in Chrome DevTools using the
 * chrome.devtools.panels API so it appears as a first-class tab alongside
 * Elements, Console, Network, etc.
 *
 * This script has access to chrome.devtools.* APIs but NOT to the DOM of the
 * inspected page. All UI logic lives in panel.js which runs inside panel.html.
 */

chrome.devtools.panels.create(
    "Defender XRay",    // Title shown in the DevTools tab bar
    "icons/icon16.png", // Icon shown next to the title
    "panel.html",       // The HTML page rendered as the panel content
    (_panel) => {
        // The panel has been created. No further initialisation is needed here
        // because panel.js bootstraps itself when panel.html loads.
    }
);
