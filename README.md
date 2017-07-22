# gateway
System access gateway，protect access to the system,enhance throughput of system services,Load balancing and routing can be carried out
Introduce:
1:The gateway service is designed using the boost framework, ans support JSON message format;
2:The gateway service save the user connection information, user's room information,and service information of management system.
3:Different load balancing methods can be adopted according to the business, such as dynamic load balancing, consistency, HASH equilibrium .etc.

gateway 是作为系统的接入网关， 对服务进行保护 同时提升系统也业务吞吐能力，起到负载均衡以及路由选择的功能：
介绍:
1:gateway 框架主要采用开源的boost框架，支持json 报文格式（可扩展）。
2:gateway 保存连接的用户信息，用户的房间信息，以及后台服务的连接信息。可以起到房间信息转发，以及用户信息转发的功能。
3:根据不同业务，灵活采用不同的负载均衡以及路由选择策略。负载均衡采用动态平和或按房间hash等。 路由选择采用按用户一致性HASH等。
