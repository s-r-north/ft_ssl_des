/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/28 21:35:36 by snorth            #+#    #+#             */
/*   Updated: 2017/03/09 15:34:42 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memmove(void *dst, void *src, size_t len)
{
	unsigned char	*ret;
	unsigned char	*source;
	int				size;

	size = (int)len;
	ret = (unsigned char*)dst;
	source = (unsigned char*)src;
	if (source < ret)
		while (--size > -1)
			ret[size] = source[size];
	else if (ret < source)
		while (--size > -1)
			*ret++ = *source++;
	return (dst);
}
