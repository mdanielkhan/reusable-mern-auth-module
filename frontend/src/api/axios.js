import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: BASE_URL,
  withCredentials: true, 
});


let isRefreshing = false;
let queue = [];

function processQueue(error) {
  queue.forEach(({ resolve, reject }) => (error ? reject(error) : resolve()));
  queue = [];
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const { config, response } = error;
    if (!response || response.status !== 401 || config._retried || config.url?.includes('/auth/refresh')) {
      return Promise.reject(error);
    }

    if (isRefreshing) {

      return new Promise((resolve, reject) => {
        queue.push({ resolve, reject });
      })
        .then(() => api(config))
        .catch((err) => Promise.reject(err));
    }

    config._retried = true;
    isRefreshing = true;

    try {
      await api.post('/auth/refresh');
      processQueue(null);
      return api(config);
    } catch (refreshError) {
      processQueue(refreshError);
     
      return Promise.reject(error);
    } finally {
      isRefreshing = false;
    }
  }
);

export default api;
