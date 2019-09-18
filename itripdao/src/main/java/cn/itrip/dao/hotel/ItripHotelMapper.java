package cn.itrip.dao.hotel;

import cn.itrip.beans.pojo.ItripAreaDic;
import cn.itrip.beans.pojo.ItripHotel;
import cn.itrip.beans.pojo.ItripLabelDic;
import cn.itrip.beans.vo.hotel.ItripSearchFacilitiesHotelVO;
import cn.itrip.beans.vo.hotel.ItripSearchPolicyHotelVO;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * @Auther: zjm
 * @Date: 2019/9/2 15:05
 * @Description:
 */
public interface ItripHotelMapper {

    public ItripHotel getItripHotelById(@Param(value = "id") Long id)throws Exception;
    /**
     *  根据酒店ID获取商圈
     * @param id 酒店ID
     */
    public List<ItripAreaDic> getHotelAreaByHotelId(@Param(value = "id") Long id)throws Exception;

    // getItripHotelById 方法到本文档的其他位置进行查找。
    /**
     *  根据酒店ID获取特色
     * @param id 酒店ID
     */
    public List<ItripLabelDic> getHotelFeatureByHotelId(@Param(value = "id") Long id)throws Exception;

    /**
     *
     * @Description: 查询酒店设施
     *
     * @param:
     * @return:
     * @auther: xwh
     * @date: 2019/9/2 16:26
     */
    public ItripSearchFacilitiesHotelVO getItripHotelFacilitiesById(@Param(value = "id") Long id) throws Exception;


    /**
     *
     * @Description: 查询酒店政策
     *
     * @param:
     * @return:
     * @auther: xwh
     * @date: 2019/9/2 17:08
     */
    public ItripSearchPolicyHotelVO queryHotelPolicy(@Param(value = "id") Long id) throws Exception;



}
