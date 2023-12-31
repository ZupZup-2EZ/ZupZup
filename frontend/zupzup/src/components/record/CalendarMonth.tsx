import styled from 'styled-components';

import { format, addMonths, subMonths } from 'date-fns';

import NextSvg from 'assets/icons/angle-right.svg?react';
import PrevSvg from 'assets/icons/angle-left.svg?react';

interface Props {
  currentDate: Date;
  setCurrentDate: (currentDate: Date) => void;
  setSelectedDate: (selectedDate: Date | null) => void;
}

const CalendarMonth = ({
  currentDate,
  setCurrentDate,
  setSelectedDate,
}: Props) => {
  return (
    <S.Wrap>
      <PrevSvg
        onClick={() => {
          setCurrentDate(subMonths(currentDate, 1));
          setSelectedDate(null);
        }}
      />
      <S.Month>{format(currentDate, 'yyyy년 MM월')}</S.Month>
      <NextSvg
        onClick={() => {
          setCurrentDate(addMonths(currentDate, 1));
          setSelectedDate(null);
        }}
      />
    </S.Wrap>
  );
};

export default CalendarMonth;

const S = {
  Wrap: styled.div`
    display: flex;
    align-items: center;
    width: 100%;
    height: 84px;
    background-color: ${({ theme }) => theme.color.white};
    justify-content: center;
    padding-bottom: 10px;

    & svg {
      width: 20px;
      height: 20px;
      margin: 0 5px 2px;
      cursor: pointer;

      & path {
        fill: ${({ theme }) => theme.color.gray3};
      }
    }
  `,
  Month: styled.div`
    font-size: ${({ theme }) => theme.font.size.display3};
    font-family: ${({ theme }) => theme.font.family.display3};
    line-height: ${({ theme }) => theme.font.lineheight.display3};
    color: ${({ theme }) => theme.color.dark};
    margin: 0 10px;
  `,
};
