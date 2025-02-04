export const sendKmipRequest = async (request: object) => {
  const kmsUrl = import.meta.env.VITE_KMS_URL;
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
