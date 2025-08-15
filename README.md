## 踩到的坑

#### 1. react收的到cookie但是發request的時候沒有戴上 (browser=chrome)

solution: 後端需要用https, set_cookie裡secure=True，可能跟瀏覽器有關

https://github.com/FiloSottile/mkcert