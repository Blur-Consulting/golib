# api package description

## API result format
使用`api.Result`，例如:
```
// controller
func (ExampleController) Get(c echo.Context) error {
    return c.JSON(http.StatusOK, api.Result{
        Success: true,
        Result:  map[string]string{
            "k": "v",
        },
    })
}
// output:
{
    "result": {
        "k": "v"
    },
    "success": true,
    "error": {}
}
```
如果返回结果是数组，使用 `api.ArrayResult` （带有`totalCount`的结构），`api.ArrayResultMore`（带有`hasMore`的结构）

推荐自行封装以上过程，具体可参考 https://github.com/hublabs/product-api/blob/master/controllers/utils.go

## Error
- 在程序启动时执行`api.SetErrorMessagePrefix()`，指定Error信息的前缀，一般为服务名
- 在Controller中，根据情况创建`api.Error`对象，例如：
```
func (ExampleController) Get(c echo.Context) error {
    err := api.ErrorUnknow.New(nil)
    var apiError api.Error
    errors.As(err, &apiError)
    return c.JSON(apiError.Status(), api.Result{
        Success: false,
        Error:   apiError,
    })
}
```

推荐自行封装以上过程，具体可参考 https://github.com/hublabs/product-api/blob/master/controllers/utils.go

### 注意：本package有2个重要特性：
- `api.Error`实现了Golang的Error接口，所以它的对象可以作为`error`在package之间传递
例如：某个Controller调用了`models.GetAll()`，在这个函数中既有DB的错误，也有调用其他服务API的错误，那么可以这么写
```
func GetAll() error {
    // DB 相关代码
    if err != nil {
        return api.ErrorDB.New(err)
    }
    // 调用其他服务API 相关代码
    if err != nil {
        return api.ErrorRemoteService.New(err)
    }
}
```
- 如果是程序内创建的`api.Error`对象，再次调用`New()`也不会覆盖原有Error的类型，比如：
```
err := api.ErrorUnknow.New(nil)
api.ErrorDB.New(err)
// err还是"Unknown error"，不是"DB error"
```
这是为了简化错误处理的过程。因为绝大部分models层的错误都是DB错误，所以我们可以这样写
```
// models
func GetAll() error {
    // DB 相关代码
    if err != nil {
        return err
    }
    // 调用其他服务API 相关代码
    if err != nil {
        return api.ErrorRemoteService.New(err)
    }
}

// controllers
func (ExampleController) Get(c echo.Context) error {
    if err := models.GetAll(); err != nil {
        renderFail(c, api.ErrorDB.New(err))
    }
    renderSucc(c, http.StatusOK, map[string]string{
        "k": "v",
    })
}
```
如果是不同服务间传递Error，可以利用这一特性返回包括调用链的错误信息，这样可以快速定位错误服务，具体可参考
https://github.com/hublabs/common/blob/master/api/errors_test.go#L33
最后返回的结果示例：
```
{
    "success": false,
    "error": {
        "code": 10003,
        "message": "Remote service error",
        "details": "serviceB: serviceA: invalid sql"
    }
}
```
