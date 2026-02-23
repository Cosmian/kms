import type { UploadProps } from "antd";
import { Upload } from "antd";
import React from "react";

type Props = UploadProps & {
    // Ant Design Form.Item injects `value` by default; Upload doesn't accept it.
    // We intentionally swallow it so it never reaches <Upload /> and triggers warnings.
    value?: unknown;
};

export const FormUpload: React.FC<Props> = (props) => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { value, ...rest } = props;
    return <Upload {...rest} />;
};

export const FormUploadDragger: React.FC<Props> = (props) => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { value, ...rest } = props;
    return <Upload.Dragger {...rest} />;
};
