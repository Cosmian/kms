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
