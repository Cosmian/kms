export const sendKmipRequest = async (request: object) => {
  const kmsUrl = import.meta.env.VITE_KMS_URL + "/kmip/2_1";
  const response = await fetch(kmsUrl, {
      method: "POST",
      headers: {
          "Content-Type": "application/json"
      },
      body: JSON.stringify(request)
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`${response.status}: ${errorText}`);
  }

  return JSON.stringify(await response.json());
}

export const postNoTTLVRequest = async (path: string, request: object) => {
  const kmsUrl = import.meta.env.VITE_KMS_URL + path;
  const response = await fetch(kmsUrl, {
      method: "POST",
      headers: {
          "Content-Type": "application/json"
      },
      body: JSON.stringify(request)
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`${response.status}: ${errorText}`);
  }

  return await response.json();
}

export const getNoTTLVRequest = async (path: string) => {
  const kmsUrl = import.meta.env.VITE_KMS_URL + path;
  const response = await fetch(kmsUrl, {
      method: "GET",
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`${response.status}: ${errorText}`);
  }

  return await response.json();
}

export const downloadFile = (data: string | Uint8Array, filename: string, mimeType: string) => {
  const blob = new Blob([data], { type: mimeType });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  URL.revokeObjectURL(url);
};
