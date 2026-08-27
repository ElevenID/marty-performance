import http from "k6/http";
import { check } from "k6";

export const options = {
  vus: 1,
  iterations: 10,
  thresholds: {
    checks: ["rate==1"],
    http_req_failed: ["rate==0"],
  },
  tags: {
    suite: "marty-performance",
    scenario: "gateway-smoke",
  },
};

const baseUrl = __ENV.BASE_URL;

export default function () {
  const health = http.get(`${baseUrl}/health`, {
    tags: { operation: "gateway-health" },
  });
  check(health, {
    "health returns 200": (response) => response.status === 200,
    "health identifies the gateway": (response) => {
      const body = response.json();
      return body.status === "healthy" && body.service === "api-gateway";
    },
  });

  const ready = http.get(`${baseUrl}/ready`, {
    tags: { operation: "stack-readiness" },
  });
  check(ready, {
    "readiness returns 200": (response) => response.status === 200,
    "readiness reports ready": (response) => {
      const body = response.json();
      return body.status === "ready" && body.service === "api-gateway";
    },
  });
}
