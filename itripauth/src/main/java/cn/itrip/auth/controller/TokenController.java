package cn.itrip.auth.controller;

import cn.itrip.auth.service.TokenService;
import cn.itrip.beans.dto.Dto;
import cn.itrip.beans.vo.ItripTokenVO;
import cn.itrip.dao.common.DtoUtil;
import cn.itrip.dao.common.ErrorCode;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Calendar;

@Controller
@RequestMapping("/api")
public class TokenController {

    @Resource
    private TokenService tokenService;

    // header="token" 表示请求头中一定要带上token这个key
    @RequestMapping(value = "/validateToken", method= RequestMethod.GET, headers = "token")
    @ResponseBody
    public Dto validate(HttpServletRequest request) {
        try {
            boolean result = tokenService.validate(request.getHeader("user-agent"), request.getHeader("token"));
            if (result) {
                return DtoUtil.returnSuccess("token有效");
            } else {
                return DtoUtil.returnSuccess("token无效");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return DtoUtil.returnFail(e.getMessage(), ErrorCode.AUTH_UNKNOWN);
        }
    }

    /**
     * 退出
     */
    @RequestMapping(value="/logout", method = RequestMethod.GET,headers = "token")
    @ResponseBody
    public Dto logout(HttpServletRequest request) {
        String token = request.getHeader("token");
        try {
            boolean result = tokenService.validate(request.getHeader("user-agent"), token);
            if (result) {
                tokenService.delete(token);
                return DtoUtil.returnSuccess("退出成功！");
            } else {
                return DtoUtil.returnFail("token无效", ErrorCode.AUTH_TOKEN_INVALID);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return DtoUtil.returnFail("退出失败",ErrorCode.AUTH_TOKEN_INVALID);
        }
    }

    /**
     * 置换接口
     * @param request
     * @return
     */
    @RequestMapping(value = "/reloadToken", method = RequestMethod.POST, headers = "token")
    @ResponseBody
    public Dto reloadToken (HttpServletRequest request) {
        try {
            String token = this.tokenService.reloadToken(request.getHeader("user-agent"), request.getHeader("token"));
            ItripTokenVO vo = new ItripTokenVO(token, Calendar.getInstance().getTimeInMillis() + 2 * 60 * 60 * 1000,  Calendar.getInstance().getTimeInMillis());
            return DtoUtil.returnDataSuccess(vo);
        } catch (Exception e) {
            e.printStackTrace();
            return DtoUtil.returnFail(e.getMessage(),ErrorCode.AUTH_UNKNOWN);
        }
    }
}
