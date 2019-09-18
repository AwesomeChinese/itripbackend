package cn.itrip.auth.controller;

import cn.itrip.auth.service.UserService;
import cn.itrip.auth.service.TokenService;
import cn.itrip.beans.dto.Dto;
import cn.itrip.beans.pojo.ItripUser;
import cn.itrip.beans.vo.ItripTokenVO;
import cn.itrip.dao.common.DtoUtil;
import cn.itrip.dao.common.EmptyUtils;
import cn.itrip.dao.common.ErrorCode;
import cn.itrip.dao.common.MD5;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Calendar;

@Controller
@RequestMapping("/api")
public class LoginController {

    @Resource
    private TokenService tokenService;

    @Resource
    private UserService userService;

    @RequestMapping(value = "/dologin" , method = RequestMethod.POST)
    @ResponseBody
    public Dto login(@RequestParam String name, @RequestParam String password, HttpServletRequest request) {
        try {
            ItripUser user = userService.login(name, MD5.getMd5(password, 32));
            if (EmptyUtils.isNotEmpty(user)) { //如果用户对象不为空。
                //得到请求头中的User-Agent
                String userAgent = request.getHeader("user-agent");
                //生成Token字符串
                String token = tokenService.generateToken(userAgent, user);
                tokenService.save(token, user); //1. 将Token保存至Redis缓存数据库中
                //2. 返回生成好后的token信息。在ItripTokenVO中就保存了Token对象的所有信息。
                //下面构造方法中，参数一Token对象，参数二有效时间为2小时，参数三生成时间。
                ItripTokenVO vo = new ItripTokenVO(token, Calendar.getInstance().getTimeInMillis() + 2 * 60 * 60 * 1000,
                        Calendar.getInstance().getTimeInMillis());
                //Calendar.getInstance().getTimeInMillis();返回long型,
                //表示从1790-1-1 00:00:00到当前时间总共经过的时间的毫秒数。
                //Dto中的字段与Token的数据结构一致。
                return DtoUtil.returnDataSuccess(vo);
            } else {
                return DtoUtil.returnFail("用户密码不正确，请确认后再输入！", ErrorCode.AUTH_AUTHENTICATION_FAILED);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return DtoUtil.returnFail(e.getMessage(), ErrorCode.AUTH_AUTHENTICATION_FAILED);
        }
    }

    /**
     * 检查用户是否已注册
     * @param name
     * @return
     */
    @ApiOperation(value="用户名验证",httpMethod = "GET",
            protocols = "HTTP", produces = "application/json",
            response = Dto.class,notes="验证是否已存在该用户名")
    @RequestMapping(value="/ckusr",method=RequestMethod.GET,produces= "application/json")
    public @ResponseBody
    Dto checkUser(
            @ApiParam(name="name",value="被检查的用户名",defaultValue="test@bdqn.cn")
            @RequestParam String name) {
        try {
/* if(!validEmail(name))
      return  DtoUtil.returnFail("请使用正确的邮箱地址注册",ErrorCode.AUTH_ILLEGAL_USERCODE);*/
            if (null == userService.findByUsername(name))
            {
                return DtoUtil.returnSuccess("用户名可用");
            }
            else
            {
                return DtoUtil.returnFail("用户已存在，注册失败", ErrorCode.AUTH_USER_ALREADY_EXISTS);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return DtoUtil.returnFail(e.getMessage(), ErrorCode.AUTH_UNKNOWN);
        }
    }
}
