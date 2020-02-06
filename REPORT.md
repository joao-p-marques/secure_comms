
## (Melhoria do) Trabalho de Secure Comms

Como melhoria em relação à primeira entrega, substituímos a operação de MIC com MAC, como recomendado e pedido no enunciado.

Para isso, mudámos a operação de hash e verificação, para implementar a nova operação.

Para o MAC, usamos na mesma a chave simétrica gerada e partilhada, mas não a mesma que usamos para encriptar a mensagem. Em vez disso, geramos uma chave maior (com o algoritmo de DH), e dividimos a mesma em 2, usando a 1ª parte para encriptar as mensagens, e a 2ª para a operação de MAC.
