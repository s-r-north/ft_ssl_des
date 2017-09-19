/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/28 20:00:50 by snorth            #+#    #+#             */
/*   Updated: 2017/03/03 17:07:57 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memset(void *b, int c, size_t len)
{
	char			*ret;
	size_t			i;
	unsigned char	q;

	ret = b;
	q = (unsigned char)c;
	i = -1;
	while (++i < len)
		ret[i] = q;
	return (ret);
}
