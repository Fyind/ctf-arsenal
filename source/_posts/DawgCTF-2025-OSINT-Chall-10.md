---
title: DawgCTF 2025 OSINT Chall 10
date: 2025-04-21 17:17:20
categories: [CTF, OSINT]
tags: [OSINT, street view, Writeup]
---

# Chall 10

https://geosint.umbccd.net/Hard-chall10

查看源代码：发现它访问了 `/info.js` , 然后去 https://geosint.umbccd.net/info.json

这个也可以通过浏览器抓包获得

里面看

``` json
{
	"Easy": {
        	"chall1": {"img": "tile_6_1_3.jpeg", "height": 6, "width": 13, "heading": 0},
        	"chall2": {"img": "tile_6_1_3.jpeg", "height": 6, "width": 13, "heading": 40},
			"chall3": {"img": "tile_7_1_4.jpeg", "height": 6, "width": 11.25, "heading": 75},
        	"chall4": {"img": "tile_6_1_3.jpeg"},
        	"chall5": {"img": "tile_10_2_4.jpeg", "height": 5, "width": 10.5, "heading": 175}
		},

	"Medium": {
			"chall6": {"img": "tile_3_1_3.jpeg", "height": 6, "width": 13, "heading": -40},
        	"chall7": {"img": "tile_6_1_3.jpeg", "height": 6, "width": 13, "heading": 125},
			"chall8": {"img": "tile_6_1_3.jpeg", "heading": 90},
        	"chall9": {"img": "tile_8_3_4.jpeg", "height": 5, "width": 11.42, "heading": 0}
	},

	"Hard": {
			"chall10": {"img": "tile_6_1_3.jpeg", "height": 6, "width": 13, "heading": 0, "panoID": "RmsBpaDYvpL-TafIFO4FbA"},
        	"chall11": {"img": "tile_6_1_3.jpeg", "height": 6, "width": 13, "heading": 90},
        	"chall12": {"img": "tile_19_6_5.jpeg", "height": 4.5, "width": 9.77, "heading": 58}
	}
}
```

然后发现chall10是有panoID的

找到PanoID后，根据https://www.google.com/maps/@?api=1&map_action=pano&pano=RmsBpaDYvpL-TafIFO4FbA 访问，就可以得到这个street view的位置

## writeup

也可以不用panoID来做，首先截图给ChatGPT进行模糊定位，发现GPT说了一个非洲的位置：Botsuana 旁边。

然后查看旁边的street view，发现它旁边的拍摄street view的车是一样的，所以推测应该是这个区域附近。

然后看植被和路面，慢慢找

* 路面是灰白色的，有大石子

* 植被是有小草，有灌木，无绿色的植物

* 可以看到路的尽头，说明它不是主干道

然后慢慢找也可以找到
