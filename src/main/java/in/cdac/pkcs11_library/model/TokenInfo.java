package in.cdac.pkcs11_library.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Value;

@Value
@AllArgsConstructor
public class TokenInfo {
    Vendor vendor;
    long slotId;
    String label;
    String manufacturer;
    String model;
    String serialNumber;

    // Custom constructor for when vendor is null
    public TokenInfo(long slotId, String label, String manufacturer, String model, String serialNumber) {
        this(null, slotId, label, manufacturer, model, serialNumber);
    }

    @Override
    public String toString() {
        String vendorName = (vendor != null) ? vendor.getName() : "Unknown";
        return label + " (" + vendorName + ") [Slot " + slotId + "]";
    }
}