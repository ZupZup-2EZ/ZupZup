import axios from 'axios';

export const BASE_URL = `${import.meta.env.VITE_APP_SERVER}/api/v1`;

const instance = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request 🧑
instance.interceptors.request.use(
  config => {
    return config;
  },
  function (error) {
    console.error(error);
    return Promise.reject(error);
  },
);

// Response 🧑
instance.interceptors.response.use(
  async response => {
    return response;
  },
  async error => {
    return Promise.reject(error);
  },
);

export default instance;
