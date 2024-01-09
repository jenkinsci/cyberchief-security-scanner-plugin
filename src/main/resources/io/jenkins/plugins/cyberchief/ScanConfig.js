function updateFieldVisibility() {
    var scanTypeElement = document.getElementById("scanTypeEntry");
    var webAppScanConfigFields = document.getElementById("webAppScanConfigFields");
    var apiScanConfigFields = document.getElementById("apiScanConfigFields");
    var raiderScanConfigFields = document.getElementById("raiderScanConfigFields");
    var failOnHighVulnsField = document.getElementById("failOnHighVulns");
    var failOnHighMediumVulnsField = document.getElementById("failOnHighMediumVulns");
    var scanDetails = document.getElementById("scanDetails");

    if (scanTypeElement) {
        var selectedValue = scanTypeElement.value;

        webAppScanConfigFields.style.display = "none";
        apiScanConfigFields.style.display = "none";
        raiderScanConfigFields.style.display = "none";

        if (selectedValue === "web_app") {
            webAppScanConfigFields.style.display = "block";
        } else if (selectedValue === "api") {
            apiScanConfigFields.style.display = "block";
        } else if (selectedValue === "raider") {
            raiderScanConfigFields.style.display = "block";
            failOnHighVulnsField.checked = false;
            failOnHighMediumVulnsField.checked = false;
            scanDetails.style.display = "none";   
        }
    } else {
        console.error("Element not found");
    }
}

function disableRaiderField() {
    var frameWorksEntry = document.getElementById("frameWorksEntry");
    var servicesEntry = document.getElementById("servicesEntry");

    if (frameWorksEntry || servicesEntry) {
        if (frameWorksEntry.value !== "") {
            servicesEntry.disabled = true;
        } else if (servicesEntry.value !== "") {
            frameWorksEntry.disabled = true;
        } else {
            frameWorksEntry.disabled = false;
            servicesEntry.disabled = false;
        }
    } else {
        console.error("Entry elements not found");
    }
}

document.getElementById("scanTypeEntry").addEventListener("change", updateFieldVisibility);
document.getElementById("frameWorksEntry").addEventListener("change", disableRaiderField);
document.getElementById("servicesEntry").addEventListener("change", disableRaiderField);

updateFieldVisibility();
disableRaiderField();
