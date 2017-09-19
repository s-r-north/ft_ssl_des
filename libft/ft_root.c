/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_root.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/03/13 19:36:53 by snorth            #+#    #+#             */
/*   Updated: 2017/03/13 21:23:14 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static double	delta(double nb, double rad, double ret)
{
	return ((1 / rad) * ((nb / ft_power(ret, rad - 1)) - ret));
}

double			ft_root(double nb, int rad)
{
	double	lim;
	double	ret;
	int		sign;

	if (nb < 0 || rad == 0)
		return (1e60);
	lim = 0;
	ret = nb;
	sign = rad < 0 ? -1 : 1;
	while (ret != lim)
	{
		lim = ret;
		ret += delta(nb, (double)rad, ret);
	}
	ret = sign == -1 ? 1 / ret : ret;
	return (ret);
}
