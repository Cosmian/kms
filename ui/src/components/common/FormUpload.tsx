import type { UploadProps } from "antd";
import { Upload, message } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { MAX_UPLOAD_SIZE_BYTES, formatFileSize } from "../../utils/utils";

type Props = UploadProps & {
    // Ant Design Form.Item injects `value` by default; Upload doesn't accept it.
    // We intentionally swallow it so it never reaches <Upload /> and triggers warnings.
    value?: unknown;
    /** Maximum file size in bytes. Defaults to MAX_UPLOAD_SIZE_BYTES (30 MB). */
    maxFileSize?: number;
};

export const FormUpload: React.FC<Props> = (props) => {
    const { t } = useTranslation("common");
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { value, maxFileSize = MAX_UPLOAD_SIZE_BYTES, beforeUpload, ...rest } = props;

    const wrappedBeforeUpload: UploadProps["beforeUpload"] = (file, fileList) => {
        if (file.size > maxFileSize) {
            message.error(t("fileTooLarge", { size: formatFileSize(file.size), max: formatFileSize(maxFileSize) }));
            return Upload.LIST_IGNORE;
        }
        if (beforeUpload) {
            return beforeUpload(file, fileList);
        }
        return false;
    };

    return <Upload {...rest} beforeUpload={wrappedBeforeUpload} />;
};

export const FormUploadDragger: React.FC<Props> = (props) => {
    const { t } = useTranslation("common");
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { value, maxFileSize = MAX_UPLOAD_SIZE_BYTES, beforeUpload, ...rest } = props;

    const wrappedBeforeUpload: UploadProps["beforeUpload"] = (file, fileList) => {
        if (file.size > maxFileSize) {
            message.error(t("fileTooLarge", { size: formatFileSize(file.size), max: formatFileSize(maxFileSize) }));
            return Upload.LIST_IGNORE;
        }
        if (beforeUpload) {
            return beforeUpload(file, fileList);
        }
        return false;
    };

    return <Upload.Dragger {...rest} beforeUpload={wrappedBeforeUpload} />;
};
