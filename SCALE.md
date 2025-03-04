
# Scaling the vlei-verifier

The `vlei-verifier` is designed to verify credentials in a decentralized identity ecosystem. While it is performant and reliable for many use cases, it has inherent limitations when scaling to handle large volumes of requests or high availability requirements. This document explains these limitations, why you should use the `vlei-verifier-router` for scaling, and how to integrate the `vlei-verifier-router` into your architecture.

---

## Limitations of the vlei-verifier

### 1. **Single-Instance Bottleneck**
   - The `vlei-verifier` is designed to run as a single instance. This means:
     - It can handle only a finite number of concurrent requests, limited by the resources of the machine it runs on.
     - It cannot horizontally scale to distribute load across multiple instances.

### 2. **No Built-In Load Balancing**
   - The `vlei-verifier` does not include built-in load balancing. If you deploy multiple instances, you must manually manage traffic distribution.

### 3. **No Fault Tolerance**
   - If the `vlei-verifier` instance goes down, all verification requests will fail until the instance is restored.

### 4. **Limited High Availability**
   - The `vlei-verifier` does not support high availability out of the box. You would need to implement redundancy and failover mechanisms manually.

---

## Why Use the vlei-verifier-router?

The `vlei-verifier-router` is designed to address the scaling limitations of the `vlei-verifier`. It acts as a **load balancer** and **orchestrator** for multiple `vlei-verifier` instances, providing the following benefits:

### 1. **Horizontal Scaling**
   - The `vlei-verifier-router` can distribute incoming requests across multiple `vlei-verifier` instances, enabling horizontal scaling.

### 2. **Load Balancing**
   - It includes built-in load balancing to evenly distribute traffic, ensuring no single `vlei-verifier` instance is overwhelmed.

### 3. **Fault Tolerance**
   - The `vlei-verifier-router` monitors the health of `vlei-verifier` instances and routes traffic only to healthy instances. If an instance fails, it is automatically removed from the pool.

### 4. **High Availability**
   - By deploying multiple `vlei-verifier` instances behind the `vlei-verifier-router`, you can achieve high availability and redundancy.

### 5. **Dynamic Instance Management**
   - The `vlei-verifier-router` supports dynamic addition and removal of `vlei-verifier` instances, making it easy to scale up or down based on demand.
   
   ### 6. **Compatibility with vlei-verifier-client**

  The `vlei-verifier-router` is fully compatible with the `vlei-verifier-client` because it exposes the **same set of endpoints** as the `vlei-verifier`. This means you can switch from a single `vlei-verifier` instance to the `vlei-verifier-router` without any changes to your client code.

---

## Conclusion

While the `vlei-verifier` is a powerful tool for credential verification, it is not designed to handle large-scale or high-availability use cases on its own. By using the `vlei-verifier-router`, you can overcome these limitations and build a scalable, fault-tolerant verification system. The `vlei-verifier-router` is fully compatible with the `vlei-verifier-client`, as it exposes the same set of endpoints, making it easy to integrate into your existing architecture.


----------

For more details, refer to the [vlei-verifier-router documentation](https://github.com/GLEIF-IT/vlei-verifier-router/blob/main/README.md). 
