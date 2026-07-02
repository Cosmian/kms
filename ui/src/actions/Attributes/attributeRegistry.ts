/**
 * Central registry of all KMIP attributes used in the Attributes UI section.
 *
 * Add new attributes here once; the four Attribute* components derive their
 * filtered lists from the exports at the bottom of this file.
 */

type AttributeInputType =
    /** DatePicker — e.g. activation_date, deactivation_date */
    | "date"
    /** Select populated from get_crypto_algorithms() */
    | "algorithm"
    /** Select populated from KEY_USAGE_OPTIONS */
    | "key_usage"
    /** Select True / False */
    | "boolean"
    /** Input[type=number] */
    | "number"
    /** Plain text Input */
    | "text"
    /** Text Input labelled "{label} Value" — used for object-ID links */
    | "link";

interface AttributeEntry {
    /** snake_case name used for Set / Modify / Get WASM calls */
    value: string;
    /**
     * PascalCase KMIP Tag name used for Tag-based Delete.
     * When absent, Delete uses `value` via the current_attribute path.
     */
    deleteValue?: string;
    /** Human-readable label shown in dropdowns and form labels */
    label: string;
    /** Input widget type rendered in Set / Modify forms */
    inputType: AttributeInputType;
    /** Appears in the Set and Modify attribute selectors */
    writable: boolean;
    /** Appears in the Delete attribute selector */
    deletable: boolean;
    /** Optional help text rendered below the input in Set / Modify */
    help?: string;
    /** Optional placeholder text for text inputs */
    placeholder?: string;
}

/** Option shape returned by get_crypto_algorithms() */
export interface AlgoOption {
    value: string;
    label: string;
}

export const ATTRIBUTE_REGISTRY: AttributeEntry[] = [
    // ── Lifecycle dates ───────────────────────────────────────────────────────
    {
        value: "activation_date",
        deleteValue: "ActivationDate",
        label: "Activation Date",
        inputType: "date",
        writable: true,
        deletable: true,
    },
    {
        value: "deactivation_date",
        deleteValue: "DeactivationDate",
        label: "Deactivation Date",
        inputType: "date",
        writable: true,
        deletable: true,
    },
    {
        value: "state",
        label: "State",
        inputType: "text",
        writable: false,
        deletable: false,
    },

    // ── Cryptographic properties ──────────────────────────────────────────────
    {
        value: "cryptographic_algorithm",
        deleteValue: "CryptographicAlgorithm",
        label: "Cryptographic Algorithm",
        inputType: "algorithm",
        writable: true,
        deletable: true,
    },
    {
        value: "cryptographic_length",
        deleteValue: "CryptographicLength",
        label: "Cryptographic Length",
        inputType: "number",
        writable: true,
        deletable: true,
    },
    {
        value: "key_usage",
        deleteValue: "CryptographicUsageMask",
        label: "Key Usage",
        inputType: "key_usage",
        writable: true,
        deletable: true,
    },
    {
        value: "key_format_type",
        label: "Key Format Type",
        inputType: "text",
        writable: false,
        deletable: false,
    },
    {
        value: "object_type",
        label: "Object Type",
        inputType: "text",
        writable: false,
        deletable: false,
    },

    // ── Metadata ──────────────────────────────────────────────────────────────
    {
        value: "name",
        deleteValue: "Name",
        label: "Name",
        inputType: "text",
        writable: true,
        deletable: true,
        placeholder: "Enter object name",
    },
    {
        value: "description",
        deleteValue: "Description",
        label: "Description",
        inputType: "text",
        writable: true,
        deletable: true,
    },
    {
        value: "comment",
        deleteValue: "Comment",
        label: "Comment",
        inputType: "text",
        writable: true,
        deletable: true,
    },
    {
        value: "contact_information",
        deleteValue: "ContactInformation",
        label: "Contact Information",
        inputType: "text",
        writable: true,
        deletable: true,
    },
    {
        value: "object_group",
        deleteValue: "ObjectGroup",
        label: "Object Group",
        inputType: "text",
        writable: true,
        deletable: true,
    },

    // ── Security flags ────────────────────────────────────────────────────────
    {
        value: "sensitive",
        deleteValue: "Sensitive",
        label: "Sensitive",
        inputType: "boolean",
        writable: true,
        deletable: true,
    },
    {
        value: "extractable",
        deleteValue: "Extractable",
        label: "Extractable",
        inputType: "boolean",
        writable: true,
        deletable: true,
    },

    // ── Vendor / opaque ───────────────────────────────────────────────────────
    {
        value: "vendor_attributes",
        label: "Vendor Attributes",
        inputType: "text",
        writable: false,
        deletable: false,
    },

    // ── Rotation (user-settable) ──────────────────────────────────────────────
    {
        value: "rotate_automatic",
        label: "Auto-Rotation Enabled",
        inputType: "boolean",
        writable: true,
        deletable: false, // server explicitly blocks deletion
    },
    {
        value: "rotate_interval",
        label: "Rotation Interval (s)",
        inputType: "number",
        writable: true,
        deletable: true,
        help: "Rotation interval in seconds (e.g. 86400 for 1 day; minimum 86400 for HSM-resident keys)",
    },
    {
        value: "rotate_name",
        label: "Rotation Name (Keyset)",
        inputType: "text",
        writable: true,
        deletable: true,
    },
    {
        value: "rotate_offset",
        label: "Rotation Offset (s)",
        inputType: "number",
        writable: true,
        deletable: true,
        help: "Offset in seconds applied to the rotation schedule (can be negative)",
    },

    // ── Rotation (server-managed, display only) ───────────────────────────────
    {
        value: "rotate_date",
        label: "Last Rotation Date",
        inputType: "text",
        writable: false,
        deletable: false,
    },
    {
        value: "rotate_generation",
        label: "Rotation Generation",
        inputType: "text",
        writable: false,
        deletable: false,
    },
    {
        value: "rotate_latest",
        label: "Is Latest Generation",
        inputType: "text",
        writable: false,
        deletable: false,
    },

    // ── Object-ID links ───────────────────────────────────────────────────────
    {
        value: "public_key_id",
        label: "Public Key ID link",
        inputType: "link",
        writable: true,
        deletable: true,
    },
    {
        value: "private_key_id",
        label: "Private Key ID link",
        inputType: "link",
        writable: true,
        deletable: true,
    },
    {
        value: "certificate_id",
        label: "Certificate ID link",
        inputType: "link",
        writable: true,
        deletable: true,
    },
    {
        value: "pkcs12_certificate_id",
        label: "PKCS12 Certificate ID link",
        inputType: "link",
        writable: true,
        deletable: true,
    },
    {
        value: "pkcs12_password_certificate",
        label: "PKCS12 Password Certificate link",
        inputType: "link",
        writable: true,
        deletable: true,
    },
    {
        value: "parent_id",
        label: "Parent ID link",
        inputType: "link",
        writable: true,
        deletable: true,
    },
    {
        value: "child_id",
        label: "Child ID link",
        inputType: "link",
        writable: true,
        deletable: true,
    },
];

/** Attributes the user may Set or Modify on a KMIP object. */
export const SET_MODIFY_ATTRIBUTES = ATTRIBUTE_REGISTRY.filter((a) => a.writable);

/** Attributes the user may Delete from a KMIP object. */
export const DELETE_ATTRIBUTES = ATTRIBUTE_REGISTRY.filter((a) => a.deletable);
