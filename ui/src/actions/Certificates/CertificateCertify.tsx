import { Button, Card, Checkbox, Divider, Form, Input, InputNumber, Radio, RadioChangeEvent, Select, Space } from "antd";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface CertificateCertifyFormData {
    certificateId?: string;
    certificateSigningRequest?: Uint8Array;
    csrFormat: "pem" | "der";
    publicKeyIdToCertify?: string;
    certificateIdToReCertify?: string;
    generateKeyPair: boolean;
    subjectName?: string;
    algorithm: string;
    issuerPrivateKeyId?: string;
    issuerCertificateId?: string;
    numberOfDays: number;
    certificateExtensions?: Uint8Array;
    tags: string[];
    enrollKeyset: boolean;
    rotateInterval?: number;
    rotateOffset?: number;
}

type AlgoOption = { label: string; value: string };

const CertificateCertifyForm: React.FC = () => {
    const [form] = Form.useForm<CertificateCertifyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [certifyMethod, setCertifyMethod] = useState<string>("csr");
    const [algorithmOptions, setAlgorithmOptions] = useState<AlgoOption[]>([]);
    const { t } = useTranslation("actions");

    useEffect(() => {
        try {
            const w = wasm as unknown as { get_certificate_algorithms?: () => AlgoOption[] };
            const opts = w.get_certificate_algorithms ? w.get_certificate_algorithms() : [];
            setAlgorithmOptions(opts);
        } catch (e) {
            console.error("Error loading certificate algorithms from WASM:", e);
        }
    }, []);

    const onCertifyMethodChange = (e: RadioChangeEvent) => {
        setCertifyMethod(e.target.value);
        form.resetFields([
            "certificateSigningRequest",
            "publicKeyIdToCertify",
            "certificateIdToReCertify",
            "generateKeyPair",
            "subjectName",
            "algorithm",
            "issuerPrivateKeyId",
            "issuerCertificateId",
            "certificateExtensions",
        ]);
        if (e.target.value === "generate") {
            form.setFieldValue("generateKeyPair", true);
        }
    };

    const onFinish = async (values: CertificateCertifyFormData) => {
        // Normalize empty/whitespace-only strings to undefined so the WASM layer
        // does not attempt to look up a blank identifier on the server.
        const normalize = (v?: string) => (v?.trim() ? v.trim() : undefined);
        await execute(async () => {
            // Option 3 uses the dedicated KMIP ReCertify operation which creates a
            // new certificate with a fresh UID and links old ↔ new via replacement links.
            if (certifyMethod === "reCertify") {
                const certIdToRenew = normalize(values.certificateIdToReCertify);
                if (!certIdToRenew)
                    throw new Error(`${t("common:errorPrefix")}${t("certificateCertify.certificateIdToReCertifyRequired")}`);
                const request = wasm.re_certify_ttlv_request(
                    certIdToRenew,
                    normalize(values.issuerPrivateKeyId),
                    normalize(values.issuerCertificateId),
                    values.numberOfDays,
                    values.tags,
                );
                const result_str = await sendKmipRequest(request, serverUrl);
                if (result_str) {
                    const response = await wasm.parse_re_certify_ttlv_response(result_str);
                    const newCertId = response.UniqueIdentifier;
                    if (values.enrollKeyset) {
                        const req = wasm.set_rotate_name_ttlv_request(newCertId, newCertId);
                        await sendKmipRequest(req, serverUrl);
                    }
                    if (values.enrollKeyset && values.rotateInterval !== undefined) {
                        const req = wasm.set_rotate_interval_ttlv_request(newCertId, BigInt(values.rotateInterval));
                        await sendKmipRequest(req, serverUrl);
                    }
                    if (values.enrollKeyset && values.rotateOffset !== undefined) {
                        const req = wasm.set_rotate_offset_ttlv_request(newCertId, BigInt(values.rotateOffset));
                        await sendKmipRequest(req, serverUrl);
                    }
                    return t("certificateCertify.successReCertify", { newCertId });
                }
                return;
            }

            const request = wasm.certify_ttlv_request(
                normalize(values.certificateId),
                values.csrFormat,
                values.certificateSigningRequest,
                normalize(values.publicKeyIdToCertify),
                normalize(values.certificateIdToReCertify),
                values.generateKeyPair,
                normalize(values.subjectName),
                normalize(values.algorithm),
                normalize(values.issuerPrivateKeyId),
                normalize(values.issuerCertificateId),
                values.numberOfDays,
                values.certificateExtensions,
                values.tags,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await wasm.parse_certify_ttlv_response(result_str);
                const newCertId = response.UniqueIdentifier;
                if (values.enrollKeyset) {
                    const req = wasm.set_rotate_name_ttlv_request(newCertId, newCertId);
                    await sendKmipRequest(req, serverUrl);
                }
                if (values.enrollKeyset && values.rotateInterval !== undefined) {
                    const req = wasm.set_rotate_interval_ttlv_request(newCertId, BigInt(values.rotateInterval));
                    await sendKmipRequest(req, serverUrl);
                }
                if (values.enrollKeyset && values.rotateOffset !== undefined) {
                    const req = wasm.set_rotate_offset_ttlv_request(newCertId, BigInt(values.rotateOffset));
                    await sendKmipRequest(req, serverUrl);
                }
                return t("certificateCertify.success", { newCertId });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("certificateCertify.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("certificateCertify.intro")}</p>
                <ol className="list-decimal ml-5">
                    <li>{t("certificateCertify.methodCsr")}</li>
                    <li>{t("certificateCertify.methodPublicKey")}</li>
                    <li>{t("certificateCertify.methodReCertify")}</li>
                    <li>{t("certificateCertify.methodGenerate")}</li>
                </ol>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    csrFormat: "pem",
                    algorithm: "rsa4096",
                    numberOfDays: 365,
                    generateKeyPair: false,
                    tags: [],
                    enrollKeyset: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateCertify.certificateIdOptional")}</h3>
                        <Form.Item name="certificateId" help={t("certificateCertify.certificateIdHelp")}>
                            <Input placeholder={t("certificateCertify.enterCertificateId")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateCertify.certificationMethod")}</h3>
                        <Radio.Group onChange={onCertifyMethodChange} value={certifyMethod}>
                            <Space direction="vertical">
                                <Radio value="csr">{t("certificateCertify.radioCsr")}</Radio>
                                <Radio value="publicKey">{t("certificateCertify.radioPublicKey")}</Radio>
                                <Radio value="reCertify">{t("certificateCertify.radioReCertify")}</Radio>
                                <Radio value="generate">{t("certificateCertify.radioGenerate")}</Radio>
                            </Space>
                        </Radio.Group>

                        {certifyMethod === "csr" && (
                            <div className="mt-4">
                                <Form.Item
                                    name="certificateSigningRequest"
                                    label={t("certificateCertify.csrLabel")}
                                    rules={[{ required: true, message: t("certificateCertify.pleaseUploadCsr") }]}
                                >
                                    <FormUploadDragger
                                        beforeUpload={(file) => {
                                            const reader = new FileReader();
                                            reader.onload = (e) => {
                                                const arrayBuffer = e.target?.result;
                                                if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                                    const bytes = new Uint8Array(arrayBuffer);
                                                    form.setFieldsValue({ certificateSigningRequest: bytes });
                                                }
                                            };
                                            reader.readAsArrayBuffer(file);
                                            return false;
                                        }}
                                        maxCount={1}
                                    >
                                        <p className="ant-upload-text">{t("certificateCertify.uploadCsrText")}</p>
                                    </FormUploadDragger>
                                </Form.Item>

                                <Form.Item name="csrFormat" label={t("certificateCertify.csrFormat")} rules={[{ required: true }]}>
                                    <Radio.Group>
                                        <Radio value="pem">PEM</Radio>
                                        <Radio value="der">DER</Radio>
                                    </Radio.Group>
                                </Form.Item>
                            </div>
                        )}

                        {certifyMethod === "publicKey" && (
                            <div className="mt-4">
                                <Form.Item
                                    name="publicKeyIdToCertify"
                                    label={t("certificateCertify.publicKeyIdToCertify")}
                                    rules={[{ required: true, message: t("certificateCertify.pleaseEnterPublicKeyId") }]}
                                >
                                    <Input placeholder={t("certificateCertify.enterPublicKeyId")} />
                                </Form.Item>

                                <Form.Item
                                    name="subjectName"
                                    label={t("certificateCertify.subjectName")}
                                    rules={[{ required: true, message: t("certificateCertify.subjectNameRequired") }]}
                                    help={t("certificateCertify.subjectNameHelp")}
                                >
                                    <Input placeholder={t("certificateCertify.subjectNamePlaceholder")} />
                                </Form.Item>
                            </div>
                        )}

                        {certifyMethod === "reCertify" && (
                            <div className="mt-4">
                                <Form.Item
                                    name="certificateIdToReCertify"
                                    label={t("certificateCertify.certificateIdToReCertify")}
                                    rules={[{ required: true, message: t("certificateCertify.pleaseEnterCertificateId") }]}
                                >
                                    <Input placeholder={t("certificateCertify.enterCertificateIdToReCertify")} />
                                </Form.Item>
                            </div>
                        )}

                        {certifyMethod === "generate" && (
                            <div className="mt-4">
                                <Form.Item name="generateKeyPair" valuePropName="checked" hidden={true}>
                                    <Checkbox>{t("certificateCertify.generateKeyPair")}</Checkbox>
                                </Form.Item>

                                <Form.Item
                                    name="subjectName"
                                    label={t("certificateCertify.subjectName")}
                                    rules={[{ required: true, message: t("certificateCertify.subjectNameRequired") }]}
                                    help={t("certificateCertify.subjectNameHelp")}
                                >
                                    <Input placeholder={t("certificateCertify.subjectNamePlaceholder")} />
                                </Form.Item>

                                <Form.Item
                                    name="algorithm"
                                    label={t("certificateCertify.keyAlgorithm")}
                                    rules={[{ required: true, message: t("certificateCertify.pleaseSelectAlgorithm") }]}
                                >
                                    <Select options={algorithmOptions} data-testid="cert-algorithm-select" virtual={false} />
                                </Form.Item>
                            </div>
                        )}
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateCertify.issuerInformation")}</h3>
                        <p className="text-sm mb-4">{t("certificateCertify.issuerHint")}</p>

                        <Form.Item
                            name="issuerPrivateKeyId"
                            label={t("certificateCertify.issuerPrivateKeyId")}
                            help={t("certificateCertify.issuerPrivateKeyIdHelp")}
                        >
                            <Input placeholder={t("certificateCertify.enterIssuerPrivateKeyId")} />
                        </Form.Item>

                        <Form.Item
                            name="issuerCertificateId"
                            label={t("certificateCertify.issuerCertificateId")}
                            help={t("certificateCertify.issuerCertificateIdHelp")}
                        >
                            <Input placeholder={t("certificateCertify.enterIssuerCertificateId")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateCertify.certificateOptions")}</h3>
                        <Form.Item
                            name="numberOfDays"
                            label={t("certificateCertify.validityPeriod")}
                            rules={[{ required: true, message: t("certificateCertify.pleaseEnterDays") }]}
                            help={t("certificateCertify.validityPeriodHelp")}
                        >
                            <Input type="number" min={1} />
                        </Form.Item>

                        <Form.Item
                            name="certificateExtensions"
                            label={t("certificateCertify.x509ExtensionsFile")}
                            help={t("certificateCertify.x509ExtensionsHelp")}
                        >
                            <FormUploadDragger
                                beforeUpload={(file) => {
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const arrayBuffer = e.target?.result;
                                        if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                            const bytes = new Uint8Array(arrayBuffer);
                                            form.setFieldsValue({ certificateExtensions: bytes });
                                        }
                                    };
                                    reader.readAsArrayBuffer(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <p className="ant-upload-text">{t("certificateCertify.uploadExtensionsText")}</p>
                            </FormUploadDragger>
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("certificateCertify.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <Divider orientation="left" plain>
                            {t("certificateCertify.rotationPolicy")}
                        </Divider>

                        <Form.Item name="enrollKeyset" valuePropName="checked" help={t("certificateCertify.enrollKeysetHelp")}>
                            <Checkbox data-testid="cert-enroll-keyset">{t("certificateCertify.enrollKeyset")}</Checkbox>
                        </Form.Item>

                        <Form.Item noStyle shouldUpdate={(prev, curr) => prev.enrollKeyset !== curr.enrollKeyset}>
                            {({ getFieldValue }) =>
                                getFieldValue("enrollKeyset") ? (
                                    <>
                                        <Form.Item
                                            name="rotateInterval"
                                            label={t("certificateCertify.rotateInterval")}
                                            help={t("certificateCertify.rotateIntervalHelp")}
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={1}
                                                placeholder={t("certificateCertify.rotateIntervalPlaceholder")}
                                                data-testid="cert-rotation-interval"
                                            />
                                        </Form.Item>

                                        <Form.Item
                                            name="rotateOffset"
                                            label={t("certificateCertify.rotateOffset")}
                                            help={t("certificateCertify.rotateOffsetHelp")}
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={0}
                                                placeholder={t("certificateCertify.rotateOffsetPlaceholder")}
                                                data-testid="cert-rotation-offset"
                                            />
                                        </Form.Item>
                                    </>
                                ) : null
                            }
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("certificateCertify.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("certificateCertify.responseTitle")} />
        </div>
    );
};

export default CertificateCertifyForm;
